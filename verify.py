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


def main() -> int:
    folder = Path(__file__).resolve().parent
    suite = unittest.defaultTestLoader.discover(str(folder), pattern="test_boundary.py")
    tests = unittest.TextTestRunner(verbosity=1).run(suite)
    fixture_exit = fixtures.main()
    sources = ("boundary.py", "fixtures.py", "test_boundary.py", "verify.py")
    report = {
        "schema_version": 1,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "command": "python verify.py",
        "runtime": {"python": platform.python_version(), "implementation": platform.python_implementation(),
                    "platform": platform.system()},
        "tests_run": tests.testsRun,
        "failures": len(tests.failures), "errors": len(tests.errors), "skipped": len(tests.skipped),
        "fixture_exit_code": fixture_exit,
        "success": tests.wasSuccessful() and fixture_exit == 0,
        "source_sha256": {name: hashlib.sha256((folder / name).read_bytes()).hexdigest() for name in sources},
    }
    (folder / "test-report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"tests_run": report["tests_run"], "success": report["success"]}))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
