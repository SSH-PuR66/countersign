"""Run the implementation checks and write inspectable local evidence."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import sys
import unittest

import fixtures
import snapshot_demo
import verify_snapshot_record


def main() -> int:
    folder = Path(__file__).resolve().parent
    suite = unittest.defaultTestLoader.discover(str(folder), pattern="test_*.py")
    tests = unittest.TextTestRunner(verbosity=1).run(suite)
    fixture_exit = fixtures.main()
    snapshot_exit = snapshot_demo.main()
    try:
        verify_snapshot_record.verify_record(folder / "snapshot-report.json", folder)
        record_exit = 0
    except verify_snapshot_record.RecordInvalid:
        record_exit = 1
    sources = ("boundary.py", "fixtures.py", "test_boundary.py", "test_snapshot.py", "snapshot_demo.py", "verify_snapshot_record.py", "test_record_integrity.py", "verify.py")
    report = {
        "schema_version": 1,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "command": "python verify.py",
        "runtime": {"python": platform.python_version(), "implementation": platform.python_implementation(),
                    "platform": platform.system()},
        "tests_run": tests.testsRun,
        "failures": len(tests.failures), "errors": len(tests.errors), "skipped": len(tests.skipped),
        "fixture_exit_code": fixture_exit,
        "snapshot_exit_code": snapshot_exit,
        "record_integrity_exit_code": record_exit,
        "success": tests.wasSuccessful() and fixture_exit == 0 and snapshot_exit == 0 and record_exit == 0,
        "source_sha256": {name: hashlib.sha256((folder / name).read_bytes()).hexdigest() for name in sources},
    }
    (folder / "test-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"tests_run": report["tests_run"], "success": report["success"]}))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
