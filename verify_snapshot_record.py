"""Check saved Carbon Copy evidence without running the gate or rewriting files.

This checks record consistency and current source hashes. It does not attest that
an execution occurred, authenticate the report, or reproduce the recorded run.
Original implementation; evaluation-stage separation inspired by HarmBench.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re
from typing import Any

ROOT = Path(__file__).resolve().parent
MAX_RECORD_BYTES = 131_072
MAX_INTEGER = (1 << 53) - 1
SOURCE_NAMES = ("boundary.py", "snapshot_demo.py", "test_snapshot.py")
CASE_NAMES = frozenset({"nonce-replaced", "expiry-extended"})
CHECK_NAMES = ("input", "grant_shape", "signature", "recipient", "tool",
               "target", "arguments", "time", "one_use")


class RecordInvalid(ValueError):
    """A saved record does not satisfy the versioned evidence contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RecordInvalid(message)


def fields(value: Any, expected: set[str], path: str) -> None:
    require(type(value) is dict and set(value) == expected,
            f"{path}: missing or unknown fields")


def integer(value: Any, path: str) -> None:
    require(type(value) is int and 0 <= value <= MAX_INTEGER,
            f"{path}: expected a nonnegative exact integer")


def hex_string(value: Any, length: int, path: str) -> None:
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{%d}" % length, value) is not None,
            f"{path}: invalid lowercase hexadecimal encoding")


def text(value: Any, path: str) -> None:
    require(type(value) is str and bool(value.strip()), f"{path}: expected nonempty text")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        require(key not in result, "record: duplicate JSON member")
        result[key] = value
    return result


def _reject_constant(_: str) -> None:
    raise RecordInvalid("record: non-finite JSON number")


def read_record(path: Path) -> Any:
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_RECORD_BYTES + 1)
        require(len(raw) <= MAX_RECORD_BYTES, "record: exceeds 128 KiB")
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                          parse_constant=_reject_constant)
    except OSError as exc:
        raise RecordInvalid("record: missing or unreadable file") from exc
    except RecordInvalid:
        raise
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise RecordInvalid("record: malformed UTF-8 JSON") from exc


def validate_case(case: Any) -> str:
    fields(case, {"name", "signed_fields", "callbacks", "caller_after", "decision",
                  "ledger_nonces", "passed"}, "case")
    name = case["name"]
    require(type(name) is str and name in CASE_NAMES, "case: unknown identity")
    require(case["passed"] is True, f"{name}: saved outcome did not pass")
    signed, caller = case["signed_fields"], case["caller_after"]
    for label, item in (("signed_fields", signed), ("caller_after", caller)):
        fields(item, {"nonce", "expires_at"}, f"{name}.{label}")
        hex_string(item["nonce"], 32, f"{name}.{label}.nonce")
        integer(item["expires_at"], f"{name}.{label}.expires_at")

    nonce_case = name == "nonce-replaced"
    callbacks = case["callbacks"]
    require(type(callbacks) is list and len(callbacks) == (2 if nonce_case else 1),
            f"{name}: unexpected clock callback count")
    for callback in callbacks:
        fields(callback, {"now", "caller_nonce", "caller_expiry"}, f"{name}.callback")
        integer(callback["now"], f"{name}.callback.now")
        integer(callback["caller_expiry"], f"{name}.callback.caller_expiry")
        hex_string(callback["caller_nonce"], 32, f"{name}.callback.caller_nonce")
        require(callback["caller_nonce"] == caller["nonce"] and
                callback["caller_expiry"] == caller["expires_at"],
                f"{name}: callback and caller state disagree")

    decision = case["decision"]
    fields(decision, {"allowed", "reason", "checks"}, f"{name}.decision")
    require(decision["allowed"] is nonce_case,
            f"{name}: unexpected authorization decision")
    require(decision["reason"] == ("approved" if nonce_case else "grant_expired"),
            f"{name}: unexpected decision reason")
    checks = decision["checks"]
    require(type(checks) is list and len(checks) == len(CHECK_NAMES),
            f"{name}: incomplete decision checks")
    expected_results = [True] * 9 if nonce_case else [True] * 7 + [False, None]
    for check, check_name, expected in zip(checks, CHECK_NAMES, expected_results):
        fields(check, {"name", "ok", "detail"}, f"{name}.check")
        require(check["name"] == check_name and check["ok"] is expected,
                f"{name}: inconsistent ordered check {check_name}")
        text(check["detail"], f"{name}.check.detail")

    ledger = case["ledger_nonces"]
    require(type(ledger) is list, f"{name}: ledger_nonces must be a list")
    if nonce_case:
        require(caller["nonce"] != signed["nonce"], f"{name}: nonce was not changed")
        require(caller["expires_at"] == signed["expires_at"], f"{name}: expiry also changed")
        require(all(callback["now"] < signed["expires_at"] for callback in callbacks),
                f"{name}: approval occurred at or after signed expiry")
        require(ledger == [signed["nonce"]], f"{name}: ledger did not consume only the signed nonce")
    else:
        require(caller["nonce"] == signed["nonce"], f"{name}: nonce also changed")
        require(signed["expires_at"] <= callbacks[0]["now"] < caller["expires_at"],
                f"{name}: callback does not demonstrate an expiry extension")
        require(ledger == [], f"{name}: rejected grant consumed a nonce")
    return name


def validate_record(report: Any, source_root: Path) -> None:
    fields(report, {"schema_version", "name", "recorded_at", "execution", "cases", "passed",
                    "source_sha256", "baseline", "scope"}, "record")
    require(type(report["schema_version"]) is int and report["schema_version"] == 1,
            "record: unsupported schema version")
    require(report["name"] == "Carbon Copy", "record: unexpected experiment name")
    require(report["passed"] is True, "record: saved run did not pass")
    for label in ("recorded_at", "execution", "scope"):
        text(report[label], f"record.{label}")
    try:
        stamp = datetime.fromisoformat(report["recorded_at"])
        require(stamp.utcoffset() is not None, "record: timestamp lacks a timezone")
    except ValueError as exc:
        raise RecordInvalid("record: invalid timezone-aware timestamp") from exc

    cases = report["cases"]
    require(type(cases) is list and len(cases) == 2, "record: expected two cases")
    identities = [validate_case(case) for case in cases]
    require(set(identities) == CASE_NAMES, "record: duplicate or missing case identity")
    by_name = {case["name"]: case for case in cases}

    baseline = report["baseline"]
    fields(baseline, {"commit", "command", "observed_before_fix"}, "baseline")
    hex_string(baseline["commit"], 40, "baseline.commit")
    text(baseline["command"], "baseline.command")
    before = baseline["observed_before_fix"]
    fields(before, {"tests", "failures", "nonce_written", "expired_grant_decision"}, "baseline.result")
    require(type(before["tests"]) is int and before["tests"] == 2 and
            type(before["failures"]) is int and before["failures"] == 2,
            "baseline: expected two recorded failing regressions")
    require(before["nonce_written"] == by_name["nonce-replaced"]["caller_after"]["nonce"] and
            before["expired_grant_decision"] == "approved", "baseline: inconsistent prior outcomes")

    hashes = report["source_sha256"]
    fields(hashes, set(SOURCE_NAMES), "source_sha256")
    for name in SOURCE_NAMES:
        hex_string(hashes[name], 64, f"source_sha256.{name}")
        try:
            digest = hashlib.sha256()
            with (source_root / name).open("rb") as stream:
                for chunk in iter(lambda: stream.read(65_536), b""):
                    digest.update(chunk)
        except OSError as exc:
            raise RecordInvalid(f"source: missing or unreadable {name}") from exc
        require(digest.hexdigest() == hashes[name], f"source: SHA-256 mismatch for {name}")


def verify_record(record_path: Path, source_root: Path = ROOT) -> dict[str, Any]:
    summary: dict[str, Any] = {"verification": "saved_record_consistency", "executed": False}
    try:
        validate_record(read_record(record_path), source_root)
        return {**summary, "passed": True, "cases": 2, "sources": len(SOURCE_NAMES)}
    except RecordInvalid as exc:
        return {**summary, "passed": False, "error": str(exc)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, default=ROOT / "snapshot-report.json")
    args = parser.parse_args(argv)
    result = verify_record(args.record)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
