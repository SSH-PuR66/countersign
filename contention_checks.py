"""Exercise real process contention and corrupt independent observer inputs."""
import copy
import unittest

import contention_campaign as campaign


def mixed_rows():
    return [{"slot": 0, "worker_pid": 101, "kind": "valid", "allowed": True, "reason": "approved"},
            {"slot": 1, "worker_pid": 102, "kind": "signature_swap", "allowed": False, "reason": "bad_signature"},
            {"slot": 2, "worker_pid": 103, "kind": "valid", "allowed": False, "reason": "replay"},
            {"slot": 3, "worker_pid": 104, "kind": "argument_swap", "allowed": False, "reason": "args_mismatch"}]


class ContentionChecks(unittest.TestCase):
    def observe(self, rows=None, *, before=0, after=1):
        return campaign.inspect_phase("mixed", mixed_rows() if rows is None else rows,
                                      before=before, after=after, workers=4)

    def test_actual_spawn_workers_across_all_three_phases(self):
        report = campaign.run_campaign(rounds=2, workers=4)
        self.assertTrue(report["passed"], report["failures"])
        self.assertEqual(report["summary"]["decisions"], 24)
        self.assertEqual(report["summary"]["accepted"], 2)
        self.assertEqual(report["summary"]["consumed_grants"], 2)
        self.assertEqual(report["summary"]["observed_worker_processes"], 4)
        self.assertTrue(all(len({row["worker_pid"] for row in phase["attempts"]}) == 4
                            for phase in report["rounds"]))

    def test_valid_mixed_observation(self):
        self.assertTrue(self.observe()["passed"])

    def test_double_allow_detected(self):
        rows = mixed_rows(); rows[2].update(allowed=True, reason="approved")
        self.assertIn("wrong_accepted_count", self.observe(rows)["errors"])

    def test_reject_all_false_negative_detected(self):
        rows = mixed_rows(); rows[0].update(allowed=False, reason="replay")
        self.assertFalse(self.observe(rows, after=0)["passed"])

    def test_durable_state_disagrees_with_reported_allow(self):
        self.assertIn("wrong_durable_consumption", self.observe(after=0)["errors"])

    def test_mutation_allow_detected(self):
        rows = mixed_rows(); rows[0].update(allowed=False, reason="replay")
        rows[1].update(allowed=True, reason="approved")
        self.assertIn("mutation_not_rejected_correctly", self.observe(rows)["errors"])

    def test_missing_and_duplicate_slots_detected(self):
        rows = mixed_rows(); rows[3]["slot"] = 2
        self.assertIn("missing_or_duplicate_worker_result", self.observe(rows)["errors"])
        self.assertFalse(self.observe(rows[:-1])["passed"])

    def test_serial_worker_substitution_detected(self):
        rows = mixed_rows(); rows[3]["worker_pid"] = rows[0]["worker_pid"]
        self.assertIn("workers_were_not_distinct_processes", self.observe(rows)["errors"])

    def test_wrong_control_mix_detected(self):
        rows = mixed_rows(); rows[3].update(kind="valid", reason="replay")
        self.assertIn("wrong_control_mix", self.observe(rows)["errors"])

    def test_non_boolean_decision_detected(self):
        rows = mixed_rows(); rows[0]["allowed"] = 1
        self.assertIn("non_boolean_decision", self.observe(rows)["errors"])

    def test_rejected_wave_must_not_spend_approval(self):
        rows = [{"slot": i, "worker_pid": 101 + i, "kind": "argument_swap",
                 "allowed": False, "reason": "args_mismatch"} for i in range(4)]
        result = campaign.inspect_phase("invalid_only", rows, before=0, after=1, workers=4)
        self.assertIn("wrong_durable_consumption", result["errors"])

    def test_unknown_phase_rejected_and_observation_does_not_mutate(self):
        rows = mixed_rows(); original = copy.deepcopy(rows)
        self.observe(rows)
        self.assertEqual(rows, original)
        result = campaign.inspect_phase("unknown", rows, before=0, after=1, workers=4)
        self.assertIn("unknown_phase", result["errors"])

    def test_worker_and_round_budgets(self):
        for workers in (True, 0, 1, 3, 17, 18, 4.0):
            with self.assertRaises(ValueError):
                campaign.run_campaign(rounds=1, workers=workers)
        for rounds in (True, 0, -1, 33, 1.0):
            with self.assertRaises(ValueError):
                campaign.run_campaign(rounds=rounds, workers=2)


if __name__ == "__main__":
    unittest.main()
