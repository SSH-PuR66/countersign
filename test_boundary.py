"""Adversarial checks for state, binding, parsing, and the CLI boundary."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
import hashlib
import hmac
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from boundary import (
    ApprovalGate, CHECK_NAMES, DOMAIN, InvalidInput, MAX_INTEGER, ReplayLedger,
    TrustedContext, arguments_digest, canonical_json, issue_grant, load_strict_json,
)
from fixtures import build_vectors, run_vectors

TEST_KEY = b"public-test-key-never-use-for-live-approvals-32bytes"
NOW = 1_790_467_200
CONTEXT = TrustedContext("analyst:sergio", "research-host")
PROPOSAL = {"tool": "reports.read", "target": "report:public:42",
            "args": {"limit": 3, "options": {"appendix": False}}}


def concurrent_process_attempt(path: str, grant: dict) -> dict:
    """Runs in separate spawned interpreters on Windows."""
    gate = ApprovalGate(TEST_KEY, ReplayLedger(path), lambda: NOW)
    return gate.evaluate(deepcopy(PROPOSAL), grant, CONTEXT).to_dict()


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="call-boundary-test-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ledger.sqlite3"
        self.ledger = ReplayLedger(self.path)
        self.gate = ApprovalGate(TEST_KEY, self.ledger, lambda: NOW)
        self.proposal = deepcopy(PROPOSAL)
        self.grant = issue_grant(TEST_KEY, CONTEXT, self.proposal, now=NOW)

    def decide(self, *, proposal=None, grant=None, context=CONTEXT):
        return self.gate.evaluate(self.proposal if proposal is None else proposal,
                                  self.grant if grant is None else grant, context)

    def signed_mutation(self, field, value):
        grant = deepcopy(self.grant)
        grant["claims"][field] = value
        grant["signature"] = hmac.new(TEST_KEY, DOMAIN + canonical_json(grant["claims"]),
                                      hashlib.sha256).hexdigest()
        return grant

    def assert_denied(self, reason, **kwargs):
        decision = self.decide(**kwargs)
        self.assertFalse(decision.allowed)
        self.assertEqual(reason, decision.reason)
        self.assertEqual(list(CHECK_NAMES), [check.name for check in decision.checks])
        return decision

    def count_consumed(self):
        with closing(sqlite3.connect(self.path)) as connection:
            return connection.execute("SELECT count(*) FROM used_grants").fetchone()[0]

    def test_approved_call_commits_actual_nonce_and_time(self):
        result = self.decide()
        self.assertTrue(result.allowed)
        self.assertEqual("approved", result.reason)
        self.assertTrue(all(check.ok is True for check in result.checks))
        with closing(sqlite3.connect(self.path)) as connection:
            row = connection.execute("SELECT nonce, consumed_at FROM used_grants").fetchone()
        self.assertEqual((self.grant["claims"]["nonce"], NOW), row)

    def test_missing_approval_is_not_authorized_by_tool_availability(self):
        result = self.gate.evaluate(self.proposal, None, CONTEXT)
        self.assertEqual("grant_invalid", result.reason)
        self.assertEqual(0, self.count_consumed())

    def test_modified_signature_rejected(self):
        self.grant["signature"] = "0" * 64
        self.assert_denied("bad_signature")

    def test_signed_claim_edit_rejected(self):
        self.grant["claims"]["target"] = "report:private:42"
        self.assert_denied("bad_signature")

    def test_wrong_verifier_key_rejected(self):
        gate = ApprovalGate(b"a" * 32, self.ledger, lambda: NOW)
        self.assertEqual("bad_signature", gate.evaluate(self.proposal, self.grant, CONTEXT).reason)

    def test_signature_uses_domain_separation(self):
        self.grant["signature"] = hmac.new(TEST_KEY, canonical_json(self.grant["claims"]),
                                          hashlib.sha256).hexdigest()
        self.assert_denied("bad_signature")

    def test_signature_comparison_uses_constant_time_primitive(self):
        with patch("boundary.hmac.compare_digest", wraps=hmac.compare_digest) as compare:
            self.assertTrue(self.decide().allowed)
        self.assertEqual(2, compare.call_count)

    def test_actor_is_taken_from_host_context(self):
        self.assert_denied("recipient_mismatch", context=TrustedContext("analyst:other", CONTEXT.audience))

    def test_audience_is_taken_from_host_context(self):
        self.assert_denied("recipient_mismatch", context=TrustedContext(CONTEXT.actor, "another-host"))

    def test_proposal_cannot_supply_its_own_actor(self):
        self.proposal["actor"] = CONTEXT.actor
        self.assert_denied("input_invalid")

    def test_tool_substitution_rejected(self):
        self.proposal["tool"] = "reports.export"
        self.assert_denied("tool_mismatch")

    def test_exact_target_required_no_prefix_or_case_normalization(self):
        for target in ("report:public:42:secret", "REPORT:public:42", "report:public:420",
                       " report:public:42", "report:public:42/"):
            with self.subTest(target=target):
                proposal = deepcopy(self.proposal)
                proposal["target"] = target
                self.assert_denied("target_mismatch", proposal=proposal)

    def test_nested_argument_mutation_rejected(self):
        self.proposal["args"]["options"]["appendix"] = True
        self.assert_denied("args_mismatch")

    def test_added_argument_rejected(self):
        self.proposal["args"]["destination"] = "archive:private"
        self.assert_denied("args_mismatch")

    def test_removed_argument_rejected(self):
        del self.proposal["args"]["options"]
        self.assert_denied("args_mismatch")

    def test_boolean_and_integer_arguments_have_different_digests(self):
        self.proposal["args"]["options"]["appendix"] = 0
        self.assert_denied("args_mismatch")

    def test_object_key_reordering_is_benign(self):
        self.proposal["args"] = {"options": {"appendix": False}, "limit": 3}
        self.assertTrue(self.decide().allowed)

    def test_array_order_changes_intent(self):
        approved = deepcopy(self.proposal)
        approved["args"]["sections"] = ["methods", "findings"]
        grant = issue_grant(TEST_KEY, CONTEXT, approved, now=NOW)
        approved["args"]["sections"].reverse()
        self.assert_denied("args_mismatch", proposal=approved, grant=grant)

    def test_unicode_is_exact_without_normalization(self):
        approved = deepcopy(self.proposal)
        approved["target"] = "report:caf\u00e9"
        grant = issue_grant(TEST_KEY, CONTEXT, approved, now=NOW)
        changed = deepcopy(approved)
        changed["target"] = "report:cafe\u0301"
        self.assert_denied("target_mismatch", proposal=changed, grant=grant)
        self.assertTrue(self.decide(proposal=approved, grant=grant).allowed)

    def test_expiry_is_exclusive(self):
        grant = issue_grant(TEST_KEY, CONTEXT, self.proposal, now=NOW - 60)
        self.assert_denied("grant_expired", grant=grant)

    def test_one_second_before_expiry_is_valid(self):
        grant = issue_grant(TEST_KEY, CONTEXT, self.proposal, now=NOW - 59)
        self.assertTrue(self.decide(grant=grant).allowed)

    def test_future_issued_time_is_rejected(self):
        grant = issue_grant(TEST_KEY, CONTEXT, self.proposal, now=NOW + 1)
        self.assert_denied("future_grant", grant=grant)

    def test_window_limits_even_when_correctly_signed(self):
        for end in (NOW - 1, NOW, NOW + 301):
            with self.subTest(end=end):
                self.assert_denied("invalid_window", grant=self.signed_mutation("expires_at", end))

    def test_boolean_timestamps_and_version_fail_closed(self):
        for field in ("issued_at", "expires_at", "version"):
            with self.subTest(field=field):
                self.assert_denied("grant_invalid", grant=self.signed_mutation(field, True))

    def test_invalid_timestamp_types_fail_closed(self):
        for value in (-1, "1790467200", 1790467200.0, None, MAX_INTEGER + 1):
            with self.subTest(value=value):
                self.assert_denied("grant_invalid", grant=self.signed_mutation("issued_at", value))

    def test_unknown_and_missing_claims_fail_closed(self):
        extended = self.signed_mutation("superuser", True)
        self.assert_denied("grant_invalid", grant=extended)
        for field in self.grant["claims"]:
            grant = deepcopy(self.grant)
            del grant["claims"][field]
            with self.subTest(field=field):
                self.assert_denied("grant_invalid", grant=grant)

    def test_unknown_envelope_fields_fail_closed(self):
        self.grant["override"] = True
        self.assert_denied("grant_invalid")

    def test_malformed_signature_encodings_fail_closed(self):
        for value in (None, True, [], "", "f" * 63, "g" * 64, "A" * 64):
            with self.subTest(value=value):
                grant = deepcopy(self.grant)
                grant["signature"] = value
                self.assert_denied("grant_invalid", grant=grant)

    def test_nonce_and_digest_encoding_must_be_exact(self):
        for field, value in (("nonce", ""), ("nonce", "f" * 31), ("nonce", "F" * 32),
                             ("args_sha256", "h" * 64), ("args_sha256", None)):
            with self.subTest(field=field, value=value):
                self.assert_denied("grant_invalid", grant=self.signed_mutation(field, value))

    def test_replay_rejected_by_same_gate(self):
        self.assertTrue(self.decide().allowed)
        self.assert_denied("replay")
        self.assertEqual(1, self.count_consumed())

    def test_replay_rejected_after_reopening_database(self):
        self.assertTrue(self.decide().allowed)
        reopened = ReplayLedger(self.path)
        self.assertEqual(self.ledger.identity, reopened.identity)
        gate = ApprovalGate(TEST_KEY, reopened, lambda: NOW)
        self.assertEqual("replay", gate.evaluate(self.proposal, self.grant, CONTEXT).reason)

    def test_replay_rejected_by_another_process(self):
        self.assertTrue(self.decide().allowed)
        with ProcessPoolExecutor(max_workers=1) as pool:
            result = pool.submit(concurrent_process_attempt, str(self.path), self.grant).result(timeout=20)
        self.assertEqual("replay", result["reason"])

    def test_concurrent_threads_consume_exactly_once(self):
        barrier = threading.Barrier(12)

        def attempt(_):
            gate = ApprovalGate(TEST_KEY, ReplayLedger(self.path), lambda: NOW)
            barrier.wait(timeout=10)
            return gate.evaluate(deepcopy(self.proposal), deepcopy(self.grant), CONTEXT)

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(attempt, range(12)))
        self.assertEqual(1, sum(result.allowed for result in results))
        self.assertEqual(11, sum(result.reason == "replay" for result in results))
        self.assertEqual(1, self.count_consumed())

    def test_concurrent_processes_consume_exactly_once(self):
        with ProcessPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(concurrent_process_attempt, [str(self.path)] * 8, [self.grant] * 8))
        self.assertEqual(1, sum(result["allowed"] for result in results))
        self.assertEqual(7, sum(result["reason"] == "replay" for result in results))
        self.assertEqual(1, self.count_consumed())

    def test_distinct_nonces_do_not_block_each_other(self):
        grants = [issue_grant(TEST_KEY, CONTEXT, self.proposal, now=NOW) for _ in range(8)]
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda grant: self.gate.evaluate(self.proposal, grant, CONTEXT), grants))
        self.assertTrue(all(result.allowed for result in results))
        self.assertEqual(8, self.count_consumed())

    def test_rejected_call_does_not_burn_valid_approval(self):
        bad = deepcopy(self.proposal)
        bad["target"] = "report:private:42"
        self.assert_denied("target_mismatch", proposal=bad)
        self.assertEqual(0, self.count_consumed())
        self.assertTrue(self.decide().allowed)

    def test_same_nonce_with_new_claims_is_still_a_replay(self):
        self.assertTrue(self.decide().allowed)
        modified = deepcopy(self.proposal)
        modified["args"]["limit"] = 4
        grant = issue_grant(TEST_KEY, CONTEXT, modified, now=NOW, nonce=self.grant["claims"]["nonce"])
        self.assert_denied("replay", proposal=modified, grant=grant)

    def test_ledger_deletion_is_fail_closed_and_not_recreated(self):
        self.path.unlink()
        self.assert_denied("ledger_unavailable")
        self.assertFalse(self.path.exists())

    def test_replacement_ledger_identity_is_detected(self):
        old_identity = self.ledger.identity
        self.path.unlink()
        replacement = ReplayLedger(self.path)
        self.assertNotEqual(old_identity, replacement.identity)
        self.assert_denied("ledger_unavailable")

    def test_corrupt_state_is_fail_closed(self):
        self.path.write_bytes(b"not-a-sqlite-database")
        self.assert_denied("ledger_unavailable")

    def test_replay_state_cannot_be_in_memory(self):
        with self.assertRaises(InvalidInput):
            ReplayLedger(":memory:")

    def test_validity_is_rechecked_inside_commit_transaction(self):
        times = iter((NOW, NOW + 60))
        gate = ApprovalGate(TEST_KEY, self.ledger, lambda: next(times))
        result = gate.evaluate(self.proposal, self.grant, CONTEXT)
        self.assertEqual("grant_expired", result.reason)
        self.assertEqual(0, self.count_consumed())
        self.assertFalse(result.checks[-2].ok)
        self.assertIsNone(result.checks[-1].ok)

    def test_clock_rewind_during_commit_is_rejected(self):
        times = iter((NOW, NOW - 1))
        gate = ApprovalGate(TEST_KEY, self.ledger, lambda: next(times))
        self.assertEqual("future_grant", gate.evaluate(self.proposal, self.grant, CONTEXT).reason)
        self.assertEqual(0, self.count_consumed())

    def test_invalid_trusted_clock_rejected(self):
        for value in (True, NOW + 0.5, "now", -1):
            with self.subTest(value=value):
                gate = ApprovalGate(TEST_KEY, self.ledger, lambda: value)
                self.assertEqual("clock_invalid", gate.evaluate(self.proposal, self.grant, CONTEXT).reason)

    def test_unknown_proposal_fields_and_missing_fields_rejected(self):
        for field in self.proposal:
            proposal = deepcopy(self.proposal)
            del proposal[field]
            with self.subTest(field=field):
                self.assert_denied("input_invalid", proposal=proposal)
        self.proposal["trusted"] = True
        self.assert_denied("input_invalid")

    def test_non_json_argument_types_are_rejected(self):
        for value in (1.0, float("nan"), float("inf"), b"bytes", (1, 2), {1, 2}, MAX_INTEGER + 1):
            with self.subTest(value=repr(value)):
                proposal = deepcopy(self.proposal)
                proposal["args"]["extra"] = value
                self.assert_denied("input_invalid", proposal=proposal)

    def test_argument_size_and_depth_limits(self):
        oversized = deepcopy(self.proposal)
        oversized["args"]["extra"] = "x" * 16_384
        self.assert_denied("input_invalid", proposal=oversized)
        nested = {}
        for _ in range(18):
            nested = {"child": nested}
        proposal = deepcopy(self.proposal)
        proposal["args"] = nested
        self.assert_denied("input_invalid", proposal=proposal)
        proposal["args"] = {"items": [0] * 1025}
        self.assert_denied("input_invalid", proposal=proposal)

    def test_null_list_and_non_string_argument_keys_rejected(self):
        for value in (None, [], {1: "value"}):
            proposal = deepcopy(self.proposal)
            proposal["args"] = value
            self.assert_denied("input_invalid", proposal=proposal)

    def test_invalid_unicode_and_control_identifiers_fail_closed(self):
        for value in ("", "   ", "x\n", "\ud800", "x" * 1025):
            proposal = deepcopy(self.proposal)
            proposal["target"] = value
            self.assert_denied("input_invalid", proposal=proposal)
        self.proposal["args"]["invalid"] = "\ud800"
        self.assert_denied("input_invalid")

    def test_strict_json_parser_rejects_duplicate_fields_at_any_depth(self):
        for text in ('{"tool":"a","tool":"b"}', '{"args":{"limit":1,"limit":2}}'):
            with self.assertRaises(InvalidInput):
                load_strict_json(text)

    def test_strict_json_parser_rejects_nonfinite_numbers(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            with self.assertRaises(InvalidInput):
                load_strict_json('{"n":' + constant + '}')

    def test_issuer_rejects_short_keys_and_invalid_lifetimes(self):
        with self.assertRaises(InvalidInput):
            ApprovalGate(b"short", self.ledger)
        for lifetime in (True, 0, -1, 301, 1.5):
            with self.assertRaises(InvalidInput):
                issue_grant(TEST_KEY, CONTEXT, self.proposal, now=NOW, lifetime=lifetime)

    def test_fixture_report_matches_all_expected_decisions(self):
        vectors = build_vectors()
        result = run_vectors(vectors)
        self.assertTrue(all(item["matched_expected"] for item in result["scenarios"]))
        summary = result["summary"]
        self.assertEqual(summary["unauthorized_scenarios"], summary["baseline_unauthorized_allows"])
        self.assertEqual(0, summary["bounded_unauthorized_allows"])
        self.assertEqual(summary["benign_scenarios"], summary["bounded_benign_allows"])

    def test_report_is_reproducible_without_a_fixed_signing_key(self):
        first = build_vectors()
        second = build_vectors()
        self.assertEqual(first, second)
        self.assertEqual(run_vectors(first), run_vectors(second))

    def test_cli_accepts_then_persistently_rejects_replay(self):
        import time
        grant = issue_grant(TEST_KEY, CONTEXT, self.proposal, now=int(time.time()))
        packet = Path(self.temp.name) / "request.json"
        key = Path(self.temp.name) / "test.key"
        packet.write_text(json.dumps({"proposal": self.proposal, "grant": grant}), encoding="utf-8")
        key.write_text(TEST_KEY.hex(), encoding="ascii")
        command = [sys.executable, str(Path(__file__).with_name("boundary.py")),
                   "--input", str(packet), "--key-file", str(key), "--ledger", str(self.path),
                   "--actor", CONTEXT.actor, "--audience", CONTEXT.audience]
        first = subprocess.run(command, capture_output=True, text=True, timeout=10)
        second = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(0, first.returncode, first.stderr)
        self.assertEqual(2, second.returncode, second.stderr)
        self.assertEqual("approved", json.loads(first.stdout)["reason"])
        self.assertEqual("replay", json.loads(second.stdout)["reason"])
        self.assertNotIn(TEST_KEY.hex(), first.stdout + first.stderr + second.stdout + second.stderr)

    def test_cli_duplicate_fields_fail_before_ledger_creation(self):
        packet = Path(self.temp.name) / "bad.json"
        key = Path(self.temp.name) / "test.key"
        new_ledger = Path(self.temp.name) / "must-not-exist.sqlite3"
        packet.write_text('{"proposal":{},"proposal":{},"grant":null}', encoding="utf-8")
        key.write_text(TEST_KEY.hex(), encoding="ascii")
        result = subprocess.run([
            sys.executable, str(Path(__file__).with_name("boundary.py")), "--input", str(packet),
            "--key-file", str(key), "--ledger", str(new_ledger),
            "--actor", CONTEXT.actor, "--audience", CONTEXT.audience,
        ], capture_output=True, text=True, timeout=10)
        self.assertEqual(2, result.returncode)
        self.assertEqual("cli_input_invalid", json.loads(result.stdout)["reason"])
        self.assertFalse(new_ledger.exists())


if __name__ == "__main__":
    unittest.main()
