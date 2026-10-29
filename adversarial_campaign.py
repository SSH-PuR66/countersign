"""Seeded local authorization attacks and benign/replay controls; no tool execution."""
from __future__ import annotations

import argparse
from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import secrets
import sqlite3
import tempfile

from boundary import ApprovalGate, ReplayLedger, TrustedContext, issue_grant

ROOT = Path(__file__).resolve().parent
NOW = 1_792_611_200
DEFAULT_SEED = 0x51EA1B8
REASONS = {
    "tool_substitution": "tool_mismatch",
    "target_substitution": "target_mismatch",
    "nested_argument": "args_mismatch",
    "boolean_integer_confusion": "args_mismatch",
    "array_order": "args_mismatch",
    "unicode_spelling": "args_mismatch",
    "actor_substitution": "recipient_mismatch",
    "audience_substitution": "recipient_mismatch",
    "changed_signed_claim": "bad_signature",
    "expiry_boundary": "grant_expired",
    "future_window": "future_grant",
}


class Stream:
    """Documented uint32 xorshift stream, independent of Python random versions."""
    def __init__(self, seed):
        if type(seed) is not int or not 1 <= seed <= 0xFFFFFFFF:
            raise ValueError("Seed must be an integer in 1..4294967295")
        self.value = seed

    def next(self):
        value = self.value
        value ^= (value << 13) & 0xFFFFFFFF
        value ^= value >> 17
        value ^= (value << 5) & 0xFFFFFFFF
        self.value = value & 0xFFFFFFFF
        return self.value


def proposal_for(stream):
    return {
        "tool": "reports.read",
        "target": f"report:synthetic:{stream.next():08x}",
        "args": {
            "section": {"offset": stream.next() % 100_000, "label": "caf\u00e9"},
            "include_notes": True,
            "pages": [stream.next() % 100, 100 + stream.next() % 100],
            "format": "text",
        },
    }


def variants(proposal, grant, context):
    """Each row changes one binding; the oracle is the declared mutation contract."""
    for name in REASONS:
        candidate, token = deepcopy(proposal), deepcopy(grant)
        actor, audience, at = context.actor, context.audience, NOW
        if name == "tool_substitution":
            candidate["tool"] = "reports.list"
        elif name == "target_substitution":
            candidate["target"] += ":other"
        elif name == "nested_argument":
            candidate["args"]["section"]["offset"] += 1
        elif name == "boolean_integer_confusion":
            candidate["args"]["include_notes"] = 1
        elif name == "array_order":
            candidate["args"]["pages"].reverse()
        elif name == "unicode_spelling":
            candidate["args"]["section"]["label"] = "cafe\u0301"
        elif name == "actor_substitution":
            actor += ":other"
        elif name == "audience_substitution":
            audience += ":other"
        elif name == "changed_signed_claim":
            token["claims"]["expires_at"] += 1
        elif name == "expiry_boundary":
            at = NOW + 60
        elif name == "future_window":
            at = NOW - 1
        yield name, candidate, token, TrustedContext(actor, audience), at


def reordered(value):
    if type(value) is dict:
        return {key: reordered(child) for key, child in reversed(list(value.items()))}
    if type(value) is list:
        return [reordered(child) for child in value]
    return value


def ledger_count(path):
    with closing(sqlite3.connect(path)) as connection:
        return connection.execute("SELECT count(*) FROM used_grants").fetchone()[0]


def run_campaign(seed=DEFAULT_SEED, rounds=64):
    if type(rounds) is not int or not 1 <= rounds <= 512:
        raise ValueError("Rounds must be an integer in 1..512")
    stream = Stream(seed)
    key = secrets.token_bytes(32)
    context = TrustedContext("synthetic:reviewer", "local:campaign")
    records, failures = [], []
    with tempfile.TemporaryDirectory(prefix="sealbreak-campaign-") as temporary:
        path = Path(temporary) / "replay.sqlite3"
        ledger = ReplayLedger(path)
        clock = [NOW]
        gate = ApprovalGate(key, ledger, lambda: clock[0])
        for number in range(rounds):
            proposal = proposal_for(stream)
            nonce = f"{number + 1:032x}"
            grant = issue_grant(key, context, proposal, now=NOW, nonce=nonce)
            observations = []
            attacks = list(variants(proposal, grant, context))
            # Different sequences expose accidental consumption hidden by a fixed ordering.
            rotation = stream.next() % len(attacks)
            attacks = attacks[rotation:] + attacks[:rotation]
            sequence = [(name, candidate, token, recipient, at, False, REASONS[name], number)
                        for name, candidate, token, recipient, at in attacks]
            sequence += [
                ("object_order_control", reordered(proposal), grant, context, NOW, True, "approved", number + 1),
                ("same_grant_replay", proposal, grant, context, NOW, False, "replay", number + 1),
            ]
            for name, candidate, token, recipient, at, allowed, reason, used in sequence:
                clock[0] = at
                decision = gate.evaluate(candidate, token, recipient)
                consumed = ledger_count(path)
                passed = decision.allowed is allowed and decision.reason == reason and consumed == used
                observations.append({
                    "case": name, "allowed": decision.allowed, "reason": decision.reason,
                    "ledger_rows": consumed, "expected_ledger_rows": used, "passed": passed,
                })
                if not passed:
                    failures.append({"round": number, "case": name,
                                     "expected_allowed": allowed, "expected_reason": reason})
            records.append({"round": number, "proposal": proposal, "nonce": nonce,
                            "observations": observations})
        final_consumed = ledger_count(path)
    # Only public inputs and decisions leave the temporary host. Signing material is discarded.
    return {
        "schema": "sealbreak-stateful-campaign/v1",
        "seed": seed, "stream": "xorshift32(13,17,5)", "rounds": rounds,
        "summary": {
            "decisions": rounds * (len(REASONS) + 2),
            "mutation_attempts": rounds * len(REASONS),
            "benign_controls": rounds, "replay_attempts": rounds,
            "consumed_grants": final_consumed, "failures": len(failures),
        },
        "passed": not failures, "failures": failures, "records": records,
        "limits": "Local synthetic decision-only gate. Curated mutation families, no external tool or model calls. Not exhaustive security coverage.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--rounds", type=int, default=64)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = run_campaign(args.seed, args.rounds)
    except ValueError as error:
        parser.error(str(error))
    result["execution"] = {
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(), "platform": platform.system(),
        "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                          for name in ("boundary.py", "adversarial_campaign.py", "campaign_checks.py")},
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"passed": result["passed"], **result["summary"]}, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
