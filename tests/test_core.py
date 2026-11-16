import json
import unittest
from pathlib import Path

from grant_effect_audit import EvidenceError, evaluate


EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def sample(name):
    return json.loads((EXAMPLES / f"synthetic-{name}.json").read_text())


class EvidenceTests(unittest.TestCase):
    def test_positive_requires_effect_and_clean_controls(self):
        result = evaluate(sample("finding"))
        self.assertEqual(result.status, "out_of_grant_effect_observed")
        self.assertEqual(result.effect_delta, 1)

    def test_blocked_requires_reachable_target(self):
        result = evaluate(sample("blocked"))
        self.assertEqual(result.status, "no_out_of_grant_effect_observed")
        without_reachability = sample("blocked")
        without_reachability["controls"] = without_reachability["controls"][:2]
        self.assertEqual(evaluate(without_reachability).status, "inconclusive")

    def test_missing_negative_control_is_inconclusive(self):
        result = evaluate(sample("inconclusive"))
        self.assertEqual(result.status, "inconclusive")
        self.assertIn("missing_approved_token_control", result.reasons)

    def test_an_effectful_anonymous_control_invalidates_attribution(self):
        case = sample("finding")
        case["controls"][0]["effect"]["after"] = 1
        self.assertEqual(evaluate(case).status, "inconclusive")

    def test_http_success_alone_is_not_a_finding(self):
        case = sample("finding")
        case["candidate"]["effect"]["after"] = 0
        self.assertEqual(evaluate(case).status, "inconclusive")

    def test_legitimate_multi_resource_grant_is_not_flagged(self):
        case = sample("finding")
        case["grant"]["approved_resources"].append(case["target_resource"])
        self.assertEqual(evaluate(case).status, "within_grant")

    def test_client_claim_is_not_independent_grant_evidence(self):
        case = sample("finding")
        case["grant"]["source_kind"] = "client_claim"
        self.assertEqual(evaluate(case).status, "inconclusive")

    def test_untrusted_multi_resource_claim_is_inconclusive(self):
        case = sample("finding")
        case["grant"]["source_kind"] = "client_claim"
        case["grant"]["approved_resources"].append(case["target_resource"])
        self.assertEqual(evaluate(case).status, "inconclusive")

    def test_legitimate_target_control_needs_distinct_B_grant(self):
        case = sample("blocked")
        control = case["controls"][2]
        control["grant_reference"] = case["grant"]["reference"]
        with self.assertRaisesRegex(EvidenceError, "separate grant"):
            evaluate(case)

    def test_effect_intervals_must_have_distinct_references(self):
        case = sample("finding")
        case["controls"][0]["effect"]["reference"] = case["candidate"]["effect"]["reference"]
        with self.assertRaisesRegex(EvidenceError, "distinct measurement"):
            evaluate(case)

    def test_client_response_is_not_independent_effect_evidence(self):
        case = sample("finding")
        case["candidate"]["effect"]["source_kind"] = "client_response"
        self.assertEqual(evaluate(case).status, "inconclusive")

    def test_concurrent_run_is_inconclusive(self):
        case = sample("finding")
        case["run"]["isolated"] = False
        self.assertEqual(evaluate(case).status, "inconclusive")

    def test_grant_reference_must_match(self):
        case = sample("finding")
        case["candidate"]["grant_reference"] = "other-grant"
        with self.assertRaisesRegex(EvidenceError, "differs"):
            evaluate(case)

    def test_secret_bearing_fields_are_rejected(self):
        case = sample("finding")
        case["candidate"]["access_token"] = "dummy"
        with self.assertRaisesRegex(EvidenceError, "secret-bearing"):
            evaluate(case)

    def test_effect_counters_must_be_monotonic_integers(self):
        case = sample("finding")
        case["candidate"]["effect"]["after"] = -1
        with self.assertRaises(EvidenceError):
            evaluate(case)
        case = sample("finding")
        case["candidate"]["effect"]["after"] = True
        with self.assertRaises(EvidenceError):
            evaluate(case)


if __name__ == "__main__":
    unittest.main()
