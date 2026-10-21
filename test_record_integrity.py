"""Tamper checks for the read-only Carbon Copy record verifier."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import verify_snapshot_record as verifier

ROOT = Path(__file__).resolve().parent


class RecordIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.folder = Path(self.temporary.name)
        self.path = self.folder / "snapshot-report.json"
        self.record = json.loads((ROOT / "snapshot-report.json").read_text(encoding="utf-8"))
        self.original_sources = {}
        for name in verifier.SOURCE_NAMES:
            # A source file is hashed as data. Executing it would fail the test.
            content = f"raise AssertionError('source must not execute: {name}')\n".encode()
            self.original_sources[name] = content
            (self.folder / name).write_bytes(content)
            self.record["source_sha256"][name] = hashlib.sha256(content).hexdigest()
        self.write(self.record)

    def write(self, record):
        self.path.write_text(json.dumps(record), encoding="utf-8")

    def verify(self):
        return verifier.verify_record(self.path, self.folder)

    def reject(self, record, fragment):
        self.write(record)
        result = self.verify()
        self.assertIs(result["passed"], False)
        self.assertIs(result["executed"], False)
        self.assertIn(fragment, result["error"])

    def test_valid_record_is_checked_without_execution_or_writes(self):
        paths = [self.path, *(self.folder / name for name in verifier.SOURCE_NAMES)]
        before = {path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}
        self.assertEqual(self.verify(), {"verification": "saved_record_consistency",
                                       "executed": False, "passed": True,
                                       "cases": 2, "sources": 3})
        self.assertEqual({path: (path.read_bytes(), path.stat().st_mtime_ns) for path in paths}, before)

    def test_case_order_is_not_part_of_the_contract(self):
        record = deepcopy(self.record)
        record["cases"].reverse()
        self.write(record)
        self.assertTrue(self.verify()["passed"])

    def test_schema_version_rejects_boolean_and_unknown_version(self):
        for version in (True, 2, "1"):
            with self.subTest(version=version):
                record = deepcopy(self.record)
                record["schema_version"] = version
                self.reject(record, "schema version")

    def test_duplicate_and_missing_case_identities_rejected(self):
        record = deepcopy(self.record)
        record["cases"][1] = deepcopy(record["cases"][0])
        self.reject(record, "case identity")
        record["cases"].pop()
        self.reject(record, "two cases")

    def test_saved_pass_flag_is_not_accepted_as_evidence(self):
        changes = (
            (0, "allowed", False, "authorization decision"),
            (0, "reason", "replay", "decision reason"),
            (1, "allowed", True, "authorization decision"),
            (1, "reason", "approved", "decision reason"),
        )
        for index, field, value, error in changes:
            with self.subTest(index=index, field=field):
                record = deepcopy(self.record)
                record["cases"][index]["decision"][field] = value
                self.reject(record, error)

    def test_ledger_must_contain_only_signed_nonce_or_be_empty(self):
        for index, ledger in ((0, []), (0, ["b" * 32]), (0, ["a" * 32] * 2), (1, ["a" * 32])):
            with self.subTest(index=index, ledger=ledger):
                record = deepcopy(self.record)
                record["cases"][index]["ledger_nonces"] = ledger
                self.reject(record, "nonce")

    def test_ordered_checks_and_boolean_types_are_enforced(self):
        for index, position, value in ((0, 0, 1), (0, 8, None), (1, 7, True), (1, 8, False)):
            with self.subTest(index=index, position=position):
                record = deepcopy(self.record)
                record["cases"][index]["decision"]["checks"][position]["ok"] = value
                self.reject(record, "ordered check")
        record = deepcopy(self.record)
        record["cases"][0]["decision"]["checks"].reverse()
        self.reject(record, "ordered check")

    def test_callback_state_must_match_caller_state(self):
        record = deepcopy(self.record)
        record["cases"][0]["callbacks"][1]["caller_nonce"] = "c" * 32
        self.reject(record, "callback and caller")
        record = deepcopy(self.record)
        record["cases"][0]["callbacks"].pop()
        self.reject(record, "callback count")

    def test_expiry_extension_and_nonce_substitution_must_be_demonstrated(self):
        record = deepcopy(self.record)
        case = record["cases"][1]
        case["caller_after"]["expires_at"] = case["signed_fields"]["expires_at"]
        case["callbacks"][0]["caller_expiry"] = case["signed_fields"]["expires_at"]
        self.reject(record, "expiry extension")
        record = deepcopy(self.record)
        case = record["cases"][0]
        case["caller_after"]["nonce"] = case["signed_fields"]["nonce"]
        for callback in case["callbacks"]:
            callback["caller_nonce"] = case["signed_fields"]["nonce"]
        self.reject(record, "nonce was not changed")

    def test_current_source_bytes_must_match_every_reported_hash(self):
        for name in verifier.SOURCE_NAMES:
            with self.subTest(name=name):
                source = self.folder / name
                source.write_bytes(self.original_sources[name] + b"# changed\n")
                self.assertIn(f"SHA-256 mismatch for {name}", self.verify()["error"])
                source.write_bytes(self.original_sources[name])

    def test_source_names_are_fixed_and_missing_source_fails(self):
        record = deepcopy(self.record)
        record["source_sha256"]["../outside.py"] = "0" * 64
        self.reject(record, "source_sha256")
        self.write(self.record)
        (self.folder / "boundary.py").unlink()
        self.assertIn("missing or unreadable boundary.py", self.verify()["error"])

    def test_invalid_hash_and_baseline_outcomes_rejected(self):
        record = deepcopy(self.record)
        record["source_sha256"]["boundary.py"] = "z" * 64
        self.reject(record, "hexadecimal")
        record = deepcopy(self.record)
        record["baseline"]["observed_before_fix"]["expired_grant_decision"] = "grant_expired"
        self.reject(record, "prior outcomes")

    def test_malformed_missing_oversized_and_duplicate_json_rejected(self):
        bad_documents = (b"{", b"\xff", b'{"schema_version":1,"schema_version":1}',
                         b"[" * 2000 + b"]" * 2000, b'{"x":NaN}',
                         b'{"x":' + b"9" * 5000 + b"}",
                         b" " * (verifier.MAX_RECORD_BYTES + 1))
        for raw in bad_documents:
            with self.subTest(size=len(raw), prefix=raw[:12]):
                self.path.write_bytes(raw)
                result = self.verify()
                self.assertFalse(result["passed"])
                self.assertIn("record:", result["error"])
        self.path.unlink()
        self.assertIn("missing or unreadable", self.verify()["error"])

    def test_timezone_and_timestamp_types_are_checked(self):
        record = deepcopy(self.record)
        record["recorded_at"] = "2026-10-21T12:00:00"
        self.reject(record, "timestamp")
        record = deepcopy(self.record)
        record["cases"][0]["callbacks"][0]["now"] = True
        self.reject(record, "exact integer")

    def test_cli_rejects_invalid_record_with_structured_nonzero_result(self):
        self.path.write_bytes(b"invalid JSON")
        completed = subprocess.run([sys.executable, "-B", str(ROOT / "verify_snapshot_record.py"),
                                    "--record", str(self.path)], capture_output=True, text=True)
        self.assertEqual(completed.returncode, 1)
        result = json.loads(completed.stdout)
        self.assertFalse(result["passed"])
        self.assertFalse(result["executed"])
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
