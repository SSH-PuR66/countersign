"""Bounded archive parsing, evidence consistency, and determinism regressions."""
from copy import deepcopy
import contextlib
import io
import json
from pathlib import Path
import stat
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import warnings
import zipfile

import evidence_bundle as bundle

ROOT = Path(__file__).resolve().parent


def fixture_payload():
    payload = {name: (ROOT / name).read_bytes() for name in bundle.PUBLIC_FILES}
    # Verification tests use a self-consistent fixture even while the new source
    # is under test, before verify.py publishes the fresh real execution report.
    run = json.loads(payload["test-report.json"])
    run["source_sha256"] = {name: bundle.sha256(payload[name]) for name in bundle.RUN_SOURCE_NAMES}
    payload["test-report.json"] = json.dumps(run).encode()
    return payload


def archive_of(entries, compression=zipfile.ZIP_STORED, symlink=None):
    output = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w", compression=compression) as archive:
            for name, content in entries:
                entry = zipfile.ZipInfo(name, bundle.FIXED_TIME)
                # Preserve hostile spelling; ZipInfo normalizes Windows separators.
                entry.filename = name
                entry.orig_filename = name
                entry.create_system = 3
                entry.external_attr = ((stat.S_IFLNK if name == symlink else stat.S_IFREG) | 0o644) << 16
                entry.compress_type = compression
                archive.writestr(entry, content)
    return output.getvalue()


class BundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = fixture_payload()
        cls.valid = bundle.encode_bundle(cls.payload)

    def entries(self, payload=None, manifest=None):
        source = payload if payload is not None else self.payload
        return [(name, source[name]) for name in bundle.PUBLIC_FILES] + [
            (bundle.MANIFEST, manifest if manifest is not None else bundle.manifest_bytes(source))]

    def reject(self, raw, fragment):
        with self.assertRaisesRegex(bundle.BundleInvalid, fragment):
            bundle.inspect_bundle_bytes(raw)

    def test_roundtrip_validates_two_reports_and_exact_public_files(self):
        result = bundle.inspect_bundle_bytes(self.valid)
        self.assertTrue(result["passed"])
        self.assertFalse(result["executed"])
        self.assertFalse(result["extracted"])
        self.assertEqual(result["files"], len(bundle.PUBLIC_FILES))
        self.assertEqual(result["sha256"], bundle.sha256(self.valid))

    def test_identical_bytes_ignore_dictionary_order(self):
        reversed_payload = dict(reversed(list(self.payload.items())))
        self.assertEqual(bundle.encode_bundle(reversed_payload), self.valid)
        with zipfile.ZipFile(io.BytesIO(self.valid)) as archive:
            self.assertEqual(archive.namelist(), sorted(archive.namelist()))
            self.assertTrue(all(entry.date_time == bundle.FIXED_TIME for entry in archive.infolist()))

    def test_bundle_verification_never_touches_disk_or_executes_members(self):
        payload = deepcopy(self.payload)
        payload["boundary.py"] = b"raise AssertionError('bundled source was executed')\n"
        saved = json.loads(payload["snapshot-report.json"])
        saved["source_sha256"]["boundary.py"] = bundle.sha256(payload["boundary.py"])
        payload["snapshot-report.json"] = json.dumps(saved).encode()
        run = json.loads(payload["test-report.json"])
        run["source_sha256"]["boundary.py"] = bundle.sha256(payload["boundary.py"])
        payload["test-report.json"] = json.dumps(run).encode()
        raw = bundle.encode_bundle(payload)
        with patch.object(Path, "open", side_effect=AssertionError("Filesystem access")), \
             patch.object(zipfile.ZipFile, "extract", side_effect=AssertionError("Extraction")), \
             patch.object(zipfile.ZipFile, "extractall", side_effect=AssertionError("Extraction")):
            self.assertTrue(bundle.inspect_bundle_bytes(raw)["passed"])

    def test_duplicate_paths_rejected(self):
        entries = self.entries()
        entries[1] = entries[0]
        self.reject(archive_of(entries), "duplicate path")

    def test_unsafe_paths_rejected(self):
        for name in ("../private.key", "/absolute", "C:/private.key", "a\\b", "a/../b"):
            with self.subTest(name=name):
                entries = self.entries()
                entries[0] = (name, entries[0][1])
                self.reject(archive_of(entries), "unsafe path")

    def test_missing_unexpected_and_extra_files_rejected(self):
        entries = self.entries()
        self.reject(archive_of(entries[:-1]), "entry count")
        entries[0] = ("private.key", b"not public")
        self.reject(archive_of(entries), "unexpected public file")
        self.reject(archive_of(entries + [("ledger.sqlite3", b"state")]), "entry count")

    def test_compressed_bomb_rejected_before_any_member_read(self):
        entries = self.entries()
        entries[0] = (entries[0][0], b"0" * 1_000_000)
        raw = archive_of(entries, zipfile.ZIP_DEFLATED)
        with patch.object(zipfile.ZipFile, "open", side_effect=AssertionError("Member read")):
            self.reject(raw, "compressed or encrypted")

    def test_encrypted_flag_rejected(self):
        raw = bytearray(self.valid)
        directory = struct.unpack("<L", raw[-6:-2])[0]
        raw[directory + 8:directory + 10] = struct.pack("<H", 1)
        self.reject(bytes(raw), "compressed or encrypted")

    def test_non_regular_member_rejected(self):
        self.reject(archive_of(self.entries(), symlink=bundle.PUBLIC_FILES[0]), "non-regular")

    def test_size_limits_reject_declared_and_actual_excess(self):
        entries = self.entries()
        entries[0] = (entries[0][0], b"0" * (bundle.MAX_MEMBER_BYTES + 1))
        self.reject(archive_of(entries), "member size")
        self.reject(b"0" * (bundle.MAX_ARCHIVE_BYTES + 1), "size limit")
        with patch.object(bundle, "MAX_TOTAL_BYTES", 10):
            self.reject(self.valid, "total size")

    def test_truncated_and_false_directory_count_rejected(self):
        self.reject(self.valid[:-2], "end record")
        raw = bytearray(self.valid)
        raw[-12:-10] = struct.pack("<H", 65535)
        self.reject(bytes(raw), "entry count")

    def test_local_header_and_crc_discrepancies_rejected(self):
        raw = bytearray(self.valid)
        raw[14] ^= 1
        self.reject(bytes(raw), "local header")
        raw = bytearray(self.valid)
        name_size = struct.unpack("<H", raw[26:28])[0]
        raw[30 + name_size] ^= 1
        self.reject(bytes(raw), "checksum mismatch")

    def test_wrong_manifest_schema_and_duplicate_members_rejected(self):
        manifest = json.loads(bundle.manifest_bytes(self.payload))
        for version in (2, True):
            with self.subTest(version=version):
                altered = deepcopy(manifest)
                altered["schema_version"] = version
                self.reject(archive_of(self.entries(manifest=json.dumps(altered).encode())), "schema")
        manifest["files"][1] = deepcopy(manifest["files"][0])
        self.reject(archive_of(self.entries(manifest=json.dumps(manifest).encode())), "duplicate or missing")

    def test_manifest_hash_and_size_discrepancies_rejected(self):
        for field, value, reason in (("sha256", "0" * 64, "SHA-256"), ("size", 0, "byte count")):
            with self.subTest(field=field):
                manifest = json.loads(bundle.manifest_bytes(self.payload))
                manifest["files"][0][field] = value
                self.reject(archive_of(self.entries(manifest=json.dumps(manifest).encode())), reason)

    def test_malformed_and_duplicate_manifest_json_rejected(self):
        for content in (b"{", b'{"format":1,"format":2}', b"\xff"):
            with self.subTest(content=content):
                self.reject(archive_of(self.entries(manifest=content)), "manifest")

    def test_self_consistent_manifest_cannot_hide_invalid_snapshot(self):
        payload = deepcopy(self.payload)
        report = json.loads(payload["snapshot-report.json"])
        report["cases"][0]["ledger_nonces"] = ["b" * 32]
        payload["snapshot-report.json"] = json.dumps(report).encode()
        self.reject(archive_of(self.entries(payload)), "ledger did not consume")

    def test_source_and_run_report_hashes_are_independently_checked(self):
        payload = deepcopy(self.payload)
        payload["boundary.py"] += b"# changed\n"
        self.reject(archive_of(self.entries(payload)), "SHA-256 mismatch")
        payload = deepcopy(self.payload)
        payload["evidence_bundle.py"] += b"# changed\n"
        self.reject(archive_of(self.entries(payload)), "test report: SHA-256 mismatch")

    def test_report_failures_and_boolean_exit_codes_are_rejected(self):
        for field, value in (("success", False), ("errors", 1), ("fixture_exit_code", False)):
            with self.subTest(field=field):
                payload = deepcopy(self.payload)
                report = json.loads(payload["test-report.json"])
                report[field] = value
                payload["test-report.json"] = json.dumps(report).encode()
                self.reject(archive_of(self.entries(payload)), "test report")

    def test_verify_file_is_read_only_and_missing_file_is_structured(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "evidence.zip"
            path.write_bytes(self.valid)
            stamp = path.stat().st_mtime_ns
            self.assertTrue(bundle.verify_bundle(path)["passed"])
            self.assertEqual(path.read_bytes(), self.valid)
            self.assertEqual(path.stat().st_mtime_ns, stamp)
            result = bundle.verify_bundle(Path(temp) / "missing.zip")
            self.assertFalse(result["passed"])
            self.assertFalse(result["extracted"])

    def test_create_never_overwrites_an_existing_destination(self):
        with tempfile.TemporaryDirectory() as temp:
            destination = Path(temp) / "evidence.zip"
            with patch.object(bundle, "collect_public_files", return_value=self.payload), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(bundle.main(["create", str(destination)]), 0)
                self.assertEqual(bundle.main(["create", str(destination)]), 1)
            self.assertEqual(destination.read_bytes(), self.valid)

    def test_run_verifier_propagates_failed_record_result(self):
        import verify
        successful_suite = SimpleNamespace(testsRun=1, failures=[], errors=[], skipped=[],
                                            wasSuccessful=lambda: True)
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            for name in bundle.RUN_SOURCE_NAMES:
                (folder / name).write_text("# fixture\n", encoding="utf-8")
            with patch.object(verify, "__file__", str(folder / "verify.py")), \
                 patch.object(verify.unittest.defaultTestLoader, "discover", return_value=unittest.TestSuite()), \
                 patch.object(verify.unittest.TextTestRunner, "run", return_value=successful_suite), \
                 patch.object(verify.fixtures, "main", return_value=0), \
                 patch.object(verify.snapshot_demo, "main", return_value=0), \
                 patch.object(verify.verify_snapshot_record, "verify_record", return_value={"passed": False}), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(verify.main(), 1)
            report = json.loads((folder / "test-report.json").read_text(encoding="utf-8"))
            self.assertFalse(report["success"])
            self.assertEqual(report["record_integrity_exit_code"], 1)


if __name__ == "__main__":
    unittest.main()
