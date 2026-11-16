import json
import unittest

from grant_effect_audit import (
    CallResult,
    CollectionError,
    EffectSnapshot,
    GrantSnapshot,
    collect,
)


A = "http://127.0.0.1:18760/mcp"
B = "http://127.0.0.1:18761/mcp"


class FixtureAdapter:
    def __init__(self, *, vulnerable=False, isolated=True, anonymous_effect=False):
        self.vulnerable = vulnerable
        self._isolated = isolated
        self.anonymous_effect = anonymous_effect
        self.count = 0
        self.requests = 0
        self.reads = 0
        self.candidate_calls = 0

    @property
    def isolated(self):
        return self._isolated

    @property
    def http_requests(self):
        return self.requests

    def observe_grant(self):
        self.requests += 1
        return GrantSnapshot("grant-A", (A,), "server_grant_record")

    def read_effect(self, target_resource):
        self.requests += 1
        self.reads += 1
        return EffectSnapshot(self.count, "server_counter", f"state-read-{self.reads}")

    def call_anonymous(self, target_resource):
        self.requests += 1
        if self.anonymous_effect:
            self.count += 1
        return CallResult(401)

    def call_with_approved_token(self, target_resource):
        self.requests += 1
        return CallResult(401)

    def call_candidate(self, target_resource):
        self.requests += 1
        self.candidate_calls += 1
        if self.vulnerable:
            self.count += 1
        return CallResult(200 if self.vulnerable else 400)

    def observe_separate_target_grant(self, target_resource):
        self.requests += 1
        return GrantSnapshot("grant-B", (B,), "server_grant_record")

    def call_with_separate_target_grant(self, target_resource):
        self.requests += 1
        self.count += 1
        return CallResult(200)


class CollectionTests(unittest.TestCase):
    def run_case(self, adapter):
        return collect(
            adapter,
            case_id="local-case",
            target_resource=B,
            transition="refresh-resource-change",
        )

    def test_positive_path_avoids_extra_effectful_control(self):
        adapter = FixtureAdapter(vulnerable=True)
        evidence, verdict = self.run_case(adapter)
        self.assertEqual(verdict.status, "out_of_grant_effect_observed")
        self.assertEqual(len(evidence["controls"]), 2)
        self.assertEqual(adapter.count, 1)
        self.assertNotIn(
            "token", json.dumps(evidence).lower().replace("approved_token", "")
        )

    def test_blocked_path_checks_separate_B_authorization(self):
        adapter = FixtureAdapter(vulnerable=False)
        evidence, verdict = self.run_case(adapter)
        self.assertEqual(verdict.status, "no_out_of_grant_effect_observed")
        self.assertEqual(len(evidence["controls"]), 3)
        self.assertEqual(evidence["candidate"]["effect"]["after"], 0)
        self.assertEqual(adapter.count, 1)  # legitimate B control only
        self.assertEqual(evidence["run"]["http_requests"], adapter.requests)

    def test_nonisolated_run_stops_before_any_calls(self):
        adapter = FixtureAdapter(isolated=False)
        with self.assertRaisesRegex(CollectionError, "isolated"):
            self.run_case(adapter)
        self.assertEqual(adapter.requests, 0)

    def test_remote_target_requires_explicit_opt_in(self):
        adapter = FixtureAdapter()
        with self.assertRaisesRegex(CollectionError, "loopback"):
            collect(
                adapter,
                case_id="x",
                target_resource="https://service.example.test/mcp",
                transition="refresh",
            )
        self.assertEqual(adapter.requests, 0)

    def test_broken_negative_control_stops_before_candidate(self):
        adapter = FixtureAdapter(anonymous_effect=True)
        with self.assertRaisesRegex(CollectionError, "candidate skipped"):
            self.run_case(adapter)
        self.assertEqual(adapter.candidate_calls, 0)


if __name__ == "__main__":
    unittest.main()
