"""A local approval gate. It decides; it never executes a tool."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
from pathlib import Path
import re
import secrets
import sqlite3
import sys
import time
from contextlib import closing
from dataclasses import asdict, dataclass
from typing import Any, Callable

VERSION = 1
MAX_LIFETIME = 300
MAX_ARGS_BYTES = 16_384
MAX_INTEGER = (1 << 53) - 1
DOMAIN = b"call-boundary/approval/v1\x00"
CLAIM_FIELDS = frozenset({
    "version", "actor", "audience", "tool", "target", "args_sha256",
    "issued_at", "expires_at", "nonce",
})
CHECK_NAMES = (
    "input", "grant_shape", "signature", "recipient", "tool", "target",
    "arguments", "time", "one_use",
)


class InvalidInput(ValueError):
    pass


class WindowChanged(ValueError):
    """A grant became invalid while waiting for the ledger write lock."""


def _window_reason(issued: int, expires: int, now: int) -> str | None:
    return (
        "invalid_window" if not 0 < expires - issued <= MAX_LIFETIME else
        "future_grant" if issued > now else
        "grant_expired" if now >= expires else None
    )


def _fields(value: Any, names: frozenset[str]) -> None:
    if type(value) is not dict or set(value) != names:
        raise InvalidInput("Object fields do not match the contract.")


def _identifier(value: Any) -> None:
    if (type(value) is not str or not value or len(value) > 1024
            or not value.strip() or any(ord(c) < 32 for c in value)):
        raise InvalidInput("Identifier must be a nonempty bounded string.")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise InvalidInput("Identifier must contain valid Unicode.") from exc


def _json_value(value: Any, depth: int = 0) -> None:
    if depth > 16:
        raise InvalidInput("Arguments exceed the nesting limit.")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        if abs(value) > MAX_INTEGER:
            raise InvalidInput("Integer is outside the exact JSON number range.")
        return
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeError as exc:
            raise InvalidInput("Invalid Unicode in arguments.") from exc
        return
    if type(value) is list and len(value) <= 1024:
        for item in value:
            _json_value(item, depth + 1)
        return
    if type(value) is dict and len(value) <= 1024:
        for key, item in value.items():
            if type(key) is not str:
                raise InvalidInput("JSON keys must be strings.")
            _json_value(key, depth + 1)
            _json_value(item, depth + 1)
        return
    raise InvalidInput("Unsupported argument type or collection size.")


def canonical_json(value: Any) -> bytes:
    """Project-local encoding; deliberately not an RFC 8785 implementation."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def arguments_digest(args: Any) -> str:
    if type(args) is not dict:
        raise InvalidInput("Arguments must be an object.")
    _json_value(args)
    encoded = canonical_json(args)
    if len(encoded) > MAX_ARGS_BYTES:
        raise InvalidInput("Arguments exceed the byte limit.")
    return hashlib.sha256(encoded).hexdigest()


def validate_proposal(proposal: Any) -> str:
    _fields(proposal, frozenset({"tool", "target", "args"}))
    _identifier(proposal["tool"])
    _identifier(proposal["target"])
    return arguments_digest(proposal["args"])


def _key(key: Any) -> None:
    if type(key) is not bytes or len(key) < 32:
        raise InvalidInput("Use a key with at least 32 bytes.")


def _timestamp(value: Any) -> None:
    # bool is a subclass of int; it is not a timestamp.
    if type(value) is not int or not 0 <= value <= MAX_INTEGER:
        raise InvalidInput("Timestamp must be a nonnegative exact integer.")


def validate_claims(claims: Any) -> None:
    _fields(claims, CLAIM_FIELDS)
    if type(claims["version"]) is not int or claims["version"] != VERSION:
        raise InvalidInput("Unsupported grant version.")
    for name in ("actor", "audience", "tool", "target"):
        _identifier(claims[name])
    for name in ("issued_at", "expires_at"):
        _timestamp(claims[name])
    for name, size in (("args_sha256", 64), ("nonce", 32)):
        value = claims[name]
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{%d}" % size, value) is None:
            raise InvalidInput("Invalid digest or nonce encoding.")


@dataclass(frozen=True)
class TrustedContext:
    """Values established by the host's authentication and routing layer."""

    actor: str
    audience: str

    def validate(self) -> None:
        _identifier(self.actor)
        _identifier(self.audience)


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool | None
    detail: str


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    checks: tuple[Check, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def issue_grant(key: bytes, context: TrustedContext, proposal: dict[str, Any], *,
                now: int, lifetime: int = 60, nonce: str | None = None) -> dict[str, Any]:
    """Host-side example: call only AFTER the host approves this exact proposal."""
    _key(key)
    context.validate()
    digest = validate_proposal(proposal)
    _timestamp(now)
    if type(lifetime) is not int or not 1 <= lifetime <= MAX_LIFETIME:
        raise InvalidInput("Grant lifetime must be between 1 and 300 seconds.")
    claims = {
        "version": VERSION, "actor": context.actor, "audience": context.audience,
        "tool": proposal["tool"], "target": proposal["target"], "args_sha256": digest,
        "issued_at": now, "expires_at": now + lifetime,
        "nonce": secrets.token_hex(16) if nonce is None else nonce,
    }
    validate_claims(claims)
    signature = hmac.new(key, DOMAIN + canonical_json(claims), hashlib.sha256).hexdigest()
    return {"claims": claims, "signature": signature}


class ReplayLedger:
    """SQLite commits a nonce before returning allow. No automatic cleanup."""

    def __init__(self, path: str | Path):
        if str(path) == ":memory:":
            raise InvalidInput("Replay state must use a persistent file.")
        self.path = Path(path).resolve()
        with closing(sqlite3.connect(self.path, timeout=5, isolation_level=None)) as connection:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            try:
                connection.execute("CREATE TABLE IF NOT EXISTS ledger_identity "
                                   "(singleton INTEGER PRIMARY KEY CHECK(singleton=1), "
                                   "identity TEXT NOT NULL)")
                connection.execute("INSERT OR IGNORE INTO ledger_identity VALUES (1, ?)",
                                   (secrets.token_hex(16),))
                connection.execute("CREATE TABLE IF NOT EXISTS used_grants "
                                   "(nonce TEXT PRIMARY KEY, consumed_at INTEGER NOT NULL)")
                self.identity = connection.execute(
                    "SELECT identity FROM ledger_identity WHERE singleton=1").fetchone()[0]
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def consume(self, nonce: str, now: int, *, recheck: Callable[[], int]) -> bool:
        # mode=rw refuses to silently create a replacement after file deletion.
        uri = self.path.as_uri() + "?mode=rw"
        with closing(sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None)) as connection:
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("BEGIN IMMEDIATE")
            try:
                identity = connection.execute(
                    "SELECT identity FROM ledger_identity WHERE singleton=1").fetchone()
                if identity != (self.identity,):
                    raise sqlite3.DatabaseError("Replay ledger identity changed.")
                # The write lock may take time. Recheck validity inside the transaction.
                now = recheck()
                try:
                    connection.execute("INSERT INTO used_grants VALUES (?, ?)", (nonce, now))
                except sqlite3.IntegrityError:
                    connection.rollback()
                    return False
                connection.commit()
                return True
            except BaseException:
                connection.rollback()
                raise


class ApprovalGate:
    def __init__(self, key: bytes, ledger: ReplayLedger,
                 clock: Callable[[], int] = lambda: int(time.time())):
        _key(key)
        self.key = key
        self.ledger = ledger
        self.clock = clock

    def evaluate(self, proposal: Any, grant: Any, context: TrustedContext) -> Decision:
        checks: list[Check] = []

        def finish(allowed: bool, reason: str) -> Decision:
            remaining = CHECK_NAMES[len(checks):]
            return Decision(allowed, reason, tuple(checks + [
                Check(name, None, "Not evaluated after an earlier rejection.")
                for name in remaining
            ]))

        def check(name: str, ok: bool, detail: str) -> None:
            checks.append(Check(name, ok, detail))

        try:
            if type(context) is not TrustedContext:
                raise InvalidInput("Host context is required.")
            context.validate()
            digest = validate_proposal(proposal)
        except (InvalidInput, TypeError, ValueError, OverflowError, RecursionError):
            check("input", False, "Proposal or trusted context violates the input contract.")
            return finish(False, "input_invalid")
        check("input", True, "Exact proposal fields and bounded JSON arguments.")

        try:
            _fields(grant, frozenset({"claims", "signature"}))
            validate_claims(grant["claims"])
            signature = grant["signature"]
            if type(signature) is not str or re.fullmatch(r"[0-9a-f]{64}", signature) is None:
                raise InvalidInput("Malformed signature.")
        except (InvalidInput, TypeError, ValueError):
            check("grant_shape", False, "Missing, malformed, or unknown grant fields.")
            return finish(False, "grant_invalid")
        check("grant_shape", True, "Exact versioned claims and signature encodings.")
        claims = grant["claims"]
        expected = hmac.new(self.key, DOMAIN + canonical_json(claims), hashlib.sha256).hexdigest()
        valid = hmac.compare_digest(expected, signature)
        check("signature", valid, "HMAC-SHA256 checked with constant-time comparison.")
        if not valid:
            return finish(False, "bad_signature")

        recipient = claims["actor"] == context.actor and claims["audience"] == context.audience
        check("recipient", recipient, "Actor and audience match the host-supplied context.")
        if not recipient:
            return finish(False, "recipient_mismatch")
        for field, reason, detail in (
            ("tool", "tool_mismatch", "Exact tool identifier matches the approval."),
            ("target", "target_mismatch", "Exact opaque target matches the approval."),
        ):
            valid = claims[field] == proposal[field]
            check(field, valid, detail)
            if not valid:
                return finish(False, reason)
        valid = hmac.compare_digest(claims["args_sha256"], digest)
        check("arguments", valid, "SHA-256 digest covers the entire arguments object.")
        if not valid:
            return finish(False, "args_mismatch")

        try:
            now = self.clock()
            _timestamp(now)
        except (InvalidInput, TypeError, ValueError, OverflowError):
            check("time", False, "The trusted clock did not return an integer timestamp.")
            return finish(False, "clock_invalid")
        issued, expires = claims["issued_at"], claims["expires_at"]
        time_reason = _window_reason(issued, expires, now)
        check("time", time_reason is None, "Issued time <= now < expiry; lifetime <= 300 seconds.")
        if time_reason:
            return finish(False, time_reason)
        def recheck() -> int:
            try:
                commit_now = self.clock()
                _timestamp(commit_now)
            except (InvalidInput, TypeError, ValueError, OverflowError) as exc:
                raise WindowChanged("clock_invalid") from exc
            reason = _window_reason(issued, expires, commit_now)
            if reason:
                raise WindowChanged(reason)
            return commit_now

        try:
            unused = self.ledger.consume(claims["nonce"], now, recheck=recheck)
        except WindowChanged as exc:
            checks[-1] = Check("time", False, "Validity changed before the ledger commit.")
            return finish(False, str(exc))
        except (sqlite3.Error, OSError):
            check("one_use", False, "Durable replay state could not be committed.")
            return finish(False, "ledger_unavailable")
        check("one_use", unused, "Nonce committed atomically to the persistent replay ledger.")
        return finish(unused, "approved" if unused else "replay")


def load_strict_json(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise InvalidInput("Duplicate JSON member.")
            result[key] = value
        return result

    def reject_constant(_: str) -> None:
        raise InvalidInput("Non-finite JSON number.")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=reject_constant)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True,
                        help="JSON containing exactly proposal and grant")
    parser.add_argument("--actor", required=True, help="Actor from the trusted host")
    parser.add_argument("--audience", required=True, help="Audience from the trusted host")
    parser.add_argument("--key-file", type=Path, required=True,
                        help="Host secret file containing a hexadecimal key (at least 32 bytes)")
    parser.add_argument("--ledger", type=Path, required=True, help="Persistent SQLite state file")
    args = parser.parse_args()
    try:
        if args.input.stat().st_size > 65_536:
            raise InvalidInput("Input exceeds 64 KiB.")
        packet = load_strict_json(args.input.read_text(encoding="utf-8"))
        _fields(packet, frozenset({"proposal", "grant"}))
        key = bytes.fromhex(args.key_file.read_text(encoding="ascii").strip())
        gate = ApprovalGate(key, ReplayLedger(args.ledger))
        decision = gate.evaluate(packet["proposal"], packet["grant"],
                                 TrustedContext(args.actor, args.audience))
        print(json.dumps(decision.to_dict(), ensure_ascii=True))
        return 0 if decision.allowed else 2
    except (InvalidInput, ValueError, OSError, sqlite3.Error, RecursionError):
        # Do not echo attacker-controlled input or key material in diagnostics.
        print(json.dumps({"allowed": False, "reason": "cli_input_invalid", "checks": []}))
        return 2


if __name__ == "__main__":
    sys.exit(main())
