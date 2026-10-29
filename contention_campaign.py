"""Synchronized local processes contend for one synthetic approval per round."""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import closing
import copy
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import platform
import secrets
import sqlite3
import tempfile
from threading import BrokenBarrierError

from boundary import ApprovalGate, ReplayLedger, TrustedContext, issue_grant

NOW = 1_792_972_800
ROOT = Path(__file__).resolve().parent
_gate = _barrier = _context = None


def _worker_init(key, ledger_path, barrier):
    global _gate, _barrier, _context
    _context = TrustedContext("synthetic:contention", "local-contention-campaign")
    _gate = ApprovalGate(key, ReplayLedger(ledger_path), clock=lambda: NOW)
    _barrier = barrier


def _attempt(task):
    slot, kind, proposal, grant = task
    proposal, grant = copy.deepcopy(proposal), copy.deepcopy(grant)
    if kind == "argument_swap":
        proposal["args"]["document"] = "synthetic:unapproved"
    elif kind == "signature_swap":
        signature = grant["signature"]
        grant["signature"] = ("0" if signature[0] != "0" else "1") + signature[1:]
    _barrier.wait(timeout=20)
    decision = _gate.evaluate(proposal, grant, _context)
    # No key, signed envelope, or real proposal enters the public record.
    return {"slot": slot, "worker_pid": os.getpid(), "kind": kind,
            "allowed": decision.allowed, "reason": decision.reason}


def inspect_phase(phase, rows, *, before, after, workers):
    """Separate observer: verify replies and durable state, including false rejects."""
    errors = []
    if phase not in ("invalid_only", "mixed", "replay"):
        errors.append("unknown_phase")
    if len(rows) != workers or {row.get("slot") for row in rows} != set(range(workers)):
        errors.append("missing_or_duplicate_worker_result")
    if len({row.get("worker_pid") for row in rows}) != workers:
        errors.append("workers_were_not_distinct_processes")
    expected_valid = workers // 2 if phase == "mixed" else workers if phase == "replay" else 0
    if sum(row.get("kind") == "valid" for row in rows) != expected_valid:
        errors.append("wrong_control_mix")
    counts = Counter(row.get("reason") for row in rows)
    accepted = [row for row in rows if row.get("allowed") is True]
    expected_accepts = 1 if phase == "mixed" else 0
    if len(accepted) != expected_accepts:
        errors.append("wrong_accepted_count")
    if after - before != expected_accepts:
        errors.append("wrong_durable_consumption")
    for row in rows:
        kind, reason, allowed = row.get("kind"), row.get("reason"), row.get("allowed")
        if type(allowed) is not bool:
            errors.append("non_boolean_decision")
        elif kind in ("argument_swap", "signature_swap"):
            expected = "args_mismatch" if kind == "argument_swap" else "bad_signature"
            if allowed or reason != expected:
                errors.append("mutation_not_rejected_correctly")
        elif kind == "valid":
            permitted = {"approved", "replay"} if phase == "mixed" else {"replay"}
            if reason not in permitted or allowed != (reason == "approved"):
                errors.append("valid_control_result_inconsistent")
        else:
            errors.append("unknown_attempt_kind")
    return {"passed": not errors, "errors": sorted(set(errors)),
            "allowed": len(accepted), "reasons": dict(sorted(counts.items())),
            "ledger_before": before, "ledger_after": after}


def run_campaign(*, rounds=16, workers=8):
    if type(rounds) is not int or not 1 <= rounds <= 32:
        raise ValueError("rounds must be 1 through 32")
    if type(workers) is not int or not 2 <= workers <= 16 or workers % 2:
        raise ValueError("workers must be an even integer from 2 through 16")
    key = secrets.token_bytes(32)
    context = TrustedContext("synthetic:contention", "local-contention-campaign")
    records = []
    ctx = multiprocessing.get_context("spawn")
    with tempfile.TemporaryDirectory(prefix="sealbreak-contention-") as directory:
        ledger_path = str(Path(directory) / "ledger.sqlite3")
        ReplayLedger(ledger_path)
        barrier = ctx.Barrier(workers)
        with ctx.Pool(workers, initializer=_worker_init,
                      initargs=(key, ledger_path, barrier)) as pool:
            def ledger_count():
                with closing(sqlite3.connect(ledger_path)) as db:
                    return db.execute("SELECT COUNT(*) FROM used_grants").fetchone()[0]

            for index in range(rounds):
                proposal = {"tool": "synthetic.read", "target": "synthetic:record",
                            "args": {"document": f"synthetic:approved:{index}"}}
                grant = issue_grant(key, context, proposal, now=NOW, nonce=f"{index + 1:032x}")
                for phase in ("invalid_only", "mixed", "replay"):
                    kinds = [("argument_swap" if slot % 2 == 0 else "signature_swap")
                             if phase == "invalid_only" or (phase == "mixed" and slot % 2)
                             else "valid" for slot in range(workers)]
                    # Alternate which mutation occupies mixed slots between rounds.
                    if phase == "mixed" and index % 2:
                        kinds = ["argument_swap" if kind == "signature_swap" else kind for kind in kinds]
                    before = ledger_count()
                    tasks = [(slot, kind, proposal, grant) for slot, kind in enumerate(kinds)]
                    rows = pool.map_async(_attempt, tasks, chunksize=1).get(timeout=40)
                    after = ledger_count()
                    observation = inspect_phase(phase, rows, before=before, after=after, workers=workers)
                    records.append({"round": index, "phase": phase, "attempts": rows, **observation})
            consumed = ledger_count()
    all_rows = [row for record in records for row in record["attempts"]]
    reasons = Counter(row["reason"] for row in all_rows)
    failures = [{"round": r["round"], "phase": r["phase"], "errors": r["errors"]}
                for r in records if not r["passed"]]
    if consumed != rounds:
        failures.append({"round": None, "phase": "total", "errors": ["wrong_final_consumption"]})
    return {"schema": "sealbreak-contention/v1", "passed": not failures,
            "scope": "Local synthetic decision gate; no tools executed, no third-party attack measurement.",
            "method": "Persistent spawn workers wait at a process barrier for every phase; scheduling order is not deterministic.",
            "parameters": {"rounds": rounds, "workers": workers, "clock": NOW},
            "runtime": {"python": platform.python_version(), "platform": platform.system(),
                        "start_method": "spawn", "sqlite": sqlite3.sqlite_version},
            "sources": {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
                        for name in ("boundary.py", "contention_campaign.py", "contention_checks.py")},
            "summary": {"decisions": len(all_rows), "accepted": sum(row["allowed"] for row in all_rows),
                        "rejected": sum(not row["allowed"] for row in all_rows),
                        "consumed_grants": consumed, "observed_worker_processes": len({row["worker_pid"] for row in all_rows}),
                        "phase_failures": len(failures), "reasons": dict(sorted(reasons.items()))},
            "failures": failures, "rounds": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=16)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = run_campaign(rounds=args.rounds, workers=args.workers)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with args.output.open("x", encoding="utf-8") as stream:
                json.dump(result, stream, indent=2)
                stream.write("\n")
    except (ValueError, OSError, RuntimeError, BrokenBarrierError, multiprocessing.TimeoutError) as exc:
        print(json.dumps({"passed": False, "error_type": type(exc).__name__}))
        return 1
    print(json.dumps({"passed": result["passed"], **result["summary"]}, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    multiprocessing.freeze_support()
    raise SystemExit(main())
