"""Record caller/snapshot separation using the actual local ApprovalGate."""
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import secrets
import sqlite3
import tempfile

from boundary import ApprovalGate, ReplayLedger, TrustedContext, issue_grant

ROOT = Path(__file__).resolve().parent
NOW = 1792600000


def run_case(name):
    with tempfile.TemporaryDirectory(prefix="sealbreak-snapshot-") as tmp:
        path = Path(tmp) / "ledger.sqlite3"
        context = TrustedContext("local:reviewer", "carbon-copy")
        proposal = {"tool": "reports.read", "target": "report:public", "args": {"format": "text"}}
        key = secrets.token_bytes(32)
        grant = issue_grant(key, context, proposal, now=NOW, nonce="a" * 32)
        initial = {"nonce": grant["claims"]["nonce"], "expires_at": grant["claims"]["expires_at"]}
        callbacks = []

        def clock():
            if name == "nonce-replaced":
                grant["claims"]["nonce"] = "b" * 32
                value = NOW
            else:
                grant["claims"]["expires_at"] = NOW + 300
                value = NOW + 60
            callbacks.append({"now": value, "caller_nonce": grant["claims"]["nonce"],
                              "caller_expiry": grant["claims"]["expires_at"]})
            return value

        decision = ApprovalGate(key, ReplayLedger(path), clock).evaluate(proposal, grant, context)
        with closing(sqlite3.connect(path)) as connection:
            ledger = [row[0] for row in connection.execute("SELECT nonce FROM used_grants")]
        expected = (decision.allowed and ledger == [initial["nonce"]]) if name == "nonce-replaced" else (
            not decision.allowed and decision.reason == "grant_expired" and ledger == [])
        return {"name": name, "signed_fields": initial, "callbacks": callbacks,
                "caller_after": {"nonce": grant["claims"]["nonce"], "expires_at": grant["claims"]["expires_at"]},
                "decision": decision.to_dict(), "ledger_nonces": ledger, "passed": expected}


def main():
    cases = [run_case("nonce-replaced"), run_case("expiry-extended")]
    report = {"schema_version": 1, "name": "Carbon Copy", "recorded_at": datetime.now(timezone.utc).isoformat(),
              "execution": "Actual local Python ApprovalGate and temporary SQLite ledger",
              "cases": cases, "passed": all(case["passed"] for case in cases),
              "source_sha256": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                                for name in ("boundary.py", "snapshot_demo.py", "test_snapshot.py")},
              "baseline": {"commit": "42ae08e1060372638dd78b522b1c21418654e7e3",
                           "command": "python -m unittest -v test_snapshot.MutableOwnershipTests",
                           "observed_before_fix": {"tests": 2, "failures": 2,
                             "nonce_written": "b" * 32, "expired_grant_decision": "approved"}},
              "scope": "A caller-owned object changes during an injected clock callback. No operation is executed. The clock and process remain trusted; this is an API ownership regression, not remote exploitability."}
    (ROOT / "snapshot-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "cases": len(cases)}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
