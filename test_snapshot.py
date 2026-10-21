"""Ownership and bounded-copy regressions for the decision-only gate."""
from copy import deepcopy
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import boundary

KEY = b"public-regression-key-not-a-deployment-secret"
NOW = 1792600000
CONTEXT = boundary.TrustedContext("local:reviewer", "snapshot-tests")
PROPOSAL = {"tool": "reports.read", "target": "report:public",
            "args": {"sections": ["summary"], "format": "text"}}


class MutableOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ledger.sqlite3"
        self.ledger = boundary.ReplayLedger(self.path)
        self.proposal = deepcopy(PROPOSAL)
        self.grant = boundary.issue_grant(KEY, CONTEXT, self.proposal,
                                         now=NOW, nonce="a" * 32)

    def test_clock_callback_cannot_change_consumed_nonce(self):
        def clock():
            self.grant["claims"]["nonce"] = "b" * 32
            return NOW
        result = boundary.ApprovalGate(KEY, self.ledger, clock).evaluate(
            self.proposal, self.grant, CONTEXT)
        self.assertTrue(result.allowed)
        with closing(sqlite3.connect(self.path)) as connection:
            nonces = connection.execute("SELECT nonce FROM used_grants").fetchall()
        self.assertEqual(nonces, [("a" * 32,)])

    def test_clock_callback_cannot_extend_signed_expiry(self):
        def clock():
            self.grant["claims"]["expires_at"] = NOW + 300
            return NOW + 60
        result = boundary.ApprovalGate(KEY, self.ledger, clock).evaluate(
            self.proposal, self.grant, CONTEXT)
        self.assertEqual(result.reason, "grant_expired")
        with closing(sqlite3.connect(self.path)) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM used_grants").fetchone()[0], 0)


class SnapshotContractTests(unittest.TestCase):
    def test_nested_values_have_no_caller_alias(self):
        original = deepcopy(PROPOSAL)
        copied = boundary.snapshot_json(original)
        original["args"]["sections"].append("appendix")
        self.assertEqual(copied, PROPOSAL)

    def test_json_scalar_types_remain_distinct(self):
        value = {"n": None, "b": True, "i": 1, "s": "1", "a": [False, 0]}
        self.assertEqual(boundary.snapshot_json(value), value)
        self.assertIs(type(boundary.snapshot_json(True)), bool)

    def test_subclass_hooks_are_not_called(self):
        class Hostile(dict):
            def items(self):
                raise AssertionError("A user-defined hook ran")
        with self.assertRaises(boundary.InvalidInput):
            boundary.snapshot_json(Hostile())

    def test_cycles_fail_with_bounded_depth(self):
        value = []
        value.append(value)
        with self.assertRaises(boundary.InvalidInput):
            boundary.snapshot_json(value)

    def test_node_budget_bounds_broad_nested_objects(self):
        with self.assertRaises(boundary.InvalidInput):
            boundary.snapshot_json([[0] * 1024] * 8)

    def test_byte_budget_bounds_strings(self):
        with self.assertRaises(boundary.InvalidInput):
            boundary.snapshot_json("a" * 65537)

    def test_invalid_unicode_rejected(self):
        with self.assertRaises(boundary.InvalidInput):
            boundary.snapshot_json({"value": "\ud800"})

    def test_floats_rejected(self):
        for value in (1.0, float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(boundary.InvalidInput):
                boundary.snapshot_json(value)

    def test_tuple_and_non_string_key_rejected(self):
        for value in ((1, 2), {1: "one"}):
            with self.subTest(value=value), self.assertRaises(boundary.InvalidInput):
                boundary.snapshot_json(value)

    def test_proposal_remains_unchanged_by_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            proposal = deepcopy(PROPOSAL)
            grant = boundary.issue_grant(KEY, CONTEXT, proposal, now=NOW)
            expected = deepcopy((proposal, grant))
            gate = boundary.ApprovalGate(KEY, boundary.ReplayLedger(Path(tmp) / "ledger"), lambda: NOW)
            self.assertTrue(gate.evaluate(proposal, grant, CONTEXT).allowed)
            self.assertEqual((proposal, grant), expected)

    def test_issuer_uses_one_proposal_snapshot(self):
        proposal = deepcopy(PROPOSAL)
        original_digest = boundary.arguments_digest

        def digest_then_change_caller(args):
            digest = original_digest(args)
            proposal["target"] = "report:changed"
            proposal["args"]["sections"].append("extra")
            return digest

        with patch("boundary.arguments_digest", side_effect=digest_then_change_caller):
            grant = boundary.issue_grant(KEY, CONTEXT, proposal, now=NOW)
        self.assertEqual(grant["claims"]["target"], PROPOSAL["target"])
        self.assertEqual(grant["claims"]["args_sha256"], original_digest(PROPOSAL["args"]))


if __name__ == "__main__":
    unittest.main()
