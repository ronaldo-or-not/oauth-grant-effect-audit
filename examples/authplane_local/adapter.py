"""Local AuthPlane v0.2.3 adapter for the grant-effect collector interface.

The official AuthPlane server and official SDK-protected effect oracles must
already be running on the four loopback ports described in this example's
README. Credentials remain in GRANT_EFFECT_AUTHPLANE_TEMP and memory only.
"""

from grant_effect_audit import CallResult, EffectSnapshot, GrantSnapshot
import flow as fixture


class AuthPlaneLocalAdapter:
    def __init__(self):
        self.reads = 0
        self.token_a = None
        self.token_b = None

    @property
    def isolated(self):
        return True  # Fresh dedicated 127.0.0.1 instance and effect oracle.

    @property
    def http_requests(self):
        return len(fixture.events)

    def _active_grant(self):
        active = [g for g in fixture.grant_list() if not g.get("revoked_at")]
        if len(active) != 1:
            raise RuntimeError("expected exactly one active fixture grant")
        grant = active[0]
        known = {
            fixture.SETUP["a"]["id"]: fixture.SETUP["uri_a"],
            fixture.SETUP["b"]["id"]: fixture.SETUP["uri_b"],
        }
        if grant["resource_id"] not in known:
            raise RuntimeError("unexpected resource in server grant record")
        return GrantSnapshot(
            str(grant["id"]), (known[grant["resource_id"]],), "server_grant_record"
        )

    def observe_grant(self):
        result, self.token_a = fixture.authorize_and_exchange(
            "public_collector_A", fixture.SETUP["uri_a"], fixture.SETUP["uri_a"]
        )
        if self.token_a is None or result["consent_screen_target"] != "A":
            raise RuntimeError("A consent or token was not established")
        grant = self._active_grant()
        if grant.approved_resources != (fixture.SETUP["uri_a"],):
            raise RuntimeError("server grant does not match A consent")
        return grant

    def read_effect(self, target_resource):
        if target_resource != fixture.SETUP["uri_b"]:
            raise RuntimeError("unexpected target")
        self.reads += 1
        response = fixture.call(
            "GET",
            fixture.SETUP["uri_b"].replace("/mcp", "/state"),
            step=f"public_collector_state_{self.reads}",
        )
        if response.status_code != 200:
            raise RuntimeError("effect state read failed")
        return EffectSnapshot(
            response.json()["count"],
            "server_counter",
            f"independent_B_state_{self.reads}",
        )

    def call_anonymous(self, target_resource):
        result = fixture.effect(None, "B", trial="public_collector_anonymous")
        return CallResult(result["status"])

    def call_with_approved_token(self, target_resource):
        result = fixture.effect(
            self.token_a["access_token"], "B", trial="public_collector_A_token"
        )
        return CallResult(result["status"])

    def call_candidate(self, target_resource):
        refresh_result, refreshed = fixture.refresh(
            "public_collector_swap", self.token_a, "B"
        )
        if refreshed is None:
            return CallResult(refresh_result["status"])
        result = fixture.effect(
            refreshed["access_token"], "B", trial="public_collector_candidate"
        )
        return CallResult(result["status"])

    def observe_separate_target_grant(self, target_resource):
        result, self.token_b = fixture.authorize_and_exchange(
            "public_collector_B", fixture.SETUP["uri_b"], fixture.SETUP["uri_b"]
        )
        if self.token_b is None or result["consent_screen_target"] != "B":
            raise RuntimeError("B consent or token was not established")
        grant = self._active_grant()
        if grant.approved_resources != (fixture.SETUP["uri_b"],):
            raise RuntimeError("server grant does not match B consent")
        return grant

    def call_with_separate_target_grant(self, target_resource):
        result = fixture.effect(
            self.token_b["access_token"], "B", trial="public_collector_legitimate_B"
        )
        return CallResult(result["status"])


def create_adapter():
    return AuthPlaneLocalAdapter()
