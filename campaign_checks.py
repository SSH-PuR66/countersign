"""Tests of the campaign oracle, its controls, and detection sensitivity."""
import unittest
from unittest.mock import patch

import adversarial_campaign as campaign
import boundary


class CampaignChecks(unittest.TestCase):
    def test_reproducible_results_with_fresh_signing_keys(self):
        self.assertEqual(campaign.run_campaign(rounds=2), campaign.run_campaign(rounds=2))

    def test_multiple_seeds_keep_all_controls(self):
        for seed in (1, 0xFFFFFFFF, 20261028):
            result = campaign.run_campaign(seed=seed, rounds=3)
            self.assertTrue(result["passed"])
            self.assertEqual(result["summary"]["decisions"], 39)
            self.assertEqual(result["summary"]["consumed_grants"], 3)

    def test_bad_seed_types_and_bounds(self):
        for seed in (True, 0, -1, 1 << 32, "1", 1.0):
            with self.assertRaises(ValueError):
                campaign.run_campaign(seed=seed, rounds=1)

    def test_bad_round_types_and_bounds(self):
        for rounds in (True, 0, -1, 513, "1", 1.0):
            with self.assertRaises(ValueError):
                campaign.run_campaign(rounds=rounds)

    def test_misreporting_an_allow_is_detected(self):
        original = boundary.ApprovalGate.evaluate

        def wrong(gate, proposal, grant, context):
            decision = original(gate, proposal, grant, context)
            if decision.reason == "args_mismatch":
                return boundary.Decision(True, "approved", decision.checks)
            return decision

        with patch.object(boundary.ApprovalGate, "evaluate", wrong):
            result = campaign.run_campaign(rounds=1)
        self.assertFalse(result["passed"])
        self.assertEqual(result["summary"]["failures"], 4)

    def test_consumption_without_approval_is_detected(self):
        original = boundary.ApprovalGate.evaluate

        def wrong(gate, proposal, grant, context):
            decision = original(gate, proposal, grant, context)
            if decision.reason == "target_mismatch":
                gate.ledger.consume(grant["claims"]["nonce"], campaign.NOW,
                                    recheck=lambda: campaign.NOW)
            return decision

        with patch.object(boundary.ApprovalGate, "evaluate", wrong):
            result = campaign.run_campaign(rounds=1)
        self.assertFalse(result["passed"])
        self.assertTrue(any(row["case"] == "object_order_control" for row in result["failures"]))

    def test_object_order_is_a_true_benign_control(self):
        value = campaign.proposal_for(campaign.Stream(1))
        self.assertEqual(boundary.arguments_digest(value["args"]),
                         boundary.arguments_digest(campaign.reordered(value)["args"]))

    def test_xorshift_known_first_values(self):
        stream = campaign.Stream(1)
        self.assertEqual([stream.next() for _ in range(4)], [270369, 67634689, 2647435461, 307599695])


if __name__ == "__main__":
    unittest.main()
