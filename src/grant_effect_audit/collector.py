"""Collect grant-to-effect evidence through a local, service-specific adapter.

The adapter owns credentials and protocol details. This runner receives only
grant identifiers, response statuses and server-side effect snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from typing import Protocol
from urllib.parse import urlsplit

from .core import Verdict, evaluate


class CollectionError(RuntimeError):
    """The requested experiment cannot be collected safely or completely."""


@dataclass(frozen=True)
class GrantSnapshot:
    reference: str
    approved_resources: tuple[str, ...]
    source_kind: str


@dataclass(frozen=True)
class EffectSnapshot:
    count: int
    source_kind: str
    reference: str


@dataclass(frozen=True)
class CallResult:
    http_status: int


class Adapter(Protocol):
    """An authorized test adapter; methods may make HTTP requests.

    Implementations must keep tokens and credentials inside the adapter, count
    their own HTTP requests, and read effects from the target server rather
    than inferring them from the response to an attempted call.
    """

    @property
    def isolated(self) -> bool: ...

    @property
    def http_requests(self) -> int: ...

    def observe_grant(self) -> GrantSnapshot: ...

    def read_effect(self, target_resource: str) -> EffectSnapshot: ...

    def call_anonymous(self, target_resource: str) -> CallResult: ...

    def call_with_approved_token(self, target_resource: str) -> CallResult: ...

    def call_candidate(self, target_resource: str) -> CallResult: ...

    def observe_separate_target_grant(self, target_resource: str) -> GrantSnapshot: ...

    def call_with_separate_target_grant(self, target_resource: str) -> CallResult: ...


def _is_loopback(uri: str) -> bool:
    host = urlsplit(uri).hostname
    if host == "localhost":
        return True
    try:
        return bool(host and ip_address(host).is_loopback)
    except ValueError:
        return False


def collect(
    adapter: Adapter,
    *,
    case_id: str,
    target_resource: str,
    transition: str,
    allow_non_loopback: bool = False,
) -> tuple[dict, Verdict]:
    """Run controls and candidate, then return redacted evidence and verdict.

    A separate legitimate-target control is run only after a zero-effect
    candidate. This avoids one effectful call when the candidate already
    demonstrated the target effect. It does not alter the finding rule.
    """
    if not adapter.isolated:
        raise CollectionError("adapter must attest to an isolated test run")
    if not allow_non_loopback and not _is_loopback(target_resource):
        raise CollectionError("target must be loopback unless explicitly allowed")
    if not case_id.strip() or not transition.strip():
        raise CollectionError("case_id and transition must be nonempty")

    grant = adapter.observe_grant()
    if not grant.reference or not grant.approved_resources:
        raise CollectionError("adapter returned an incomplete grant")
    if target_resource in grant.approved_resources:
        raise CollectionError("target already belongs to the observed grant")

    evidence = {
        "schema_version": "1",
        "case_id": case_id,
        "run": {"isolated": True},
        "grant": {
            "reference": grant.reference,
            "source_kind": grant.source_kind,
            "approved_resources": list(grant.approved_resources),
        },
        "target_resource": target_resource,
        "controls": [],
    }

    def measured(
        kind: str, action, *, control_grant: GrantSnapshot | None = None
    ) -> dict:
        before = adapter.read_effect(target_resource)
        response = action(target_resource)
        after = adapter.read_effect(target_resource)
        if before.source_kind != after.source_kind:
            raise CollectionError(f"{kind} effect source changed during measurement")
        item = {
            "target_resource": target_resource,
            "http_status": response.http_status,
            "effect": {
                "before": before.count,
                "after": after.count,
                "source_kind": after.source_kind,
                "reference": f"{before.reference} -> {after.reference}",
            },
        }
        if kind != "candidate":
            item["kind"] = kind
        if kind == "approved_token" or kind == "candidate":
            item["grant_reference"] = grant.reference
        if control_grant is not None:
            item["grant_reference"] = control_grant.reference
            item["approved_resources"] = list(control_grant.approved_resources)
        return item

    for kind, action in (
        ("anonymous", adapter.call_anonymous),
        ("approved_token", adapter.call_with_approved_token),
    ):
        control = measured(kind, action)
        evidence["controls"].append(control)
        if control["effect"]["after"] != control["effect"]["before"]:
            raise CollectionError(
                f"{kind} control changed the target; candidate skipped"
            )
    candidate = measured("candidate", adapter.call_candidate)
    candidate["transition"] = transition
    evidence["candidate"] = candidate

    if candidate["effect"]["after"] == candidate["effect"]["before"]:
        separate_grant = adapter.observe_separate_target_grant(target_resource)
        if target_resource not in separate_grant.approved_resources:
            raise CollectionError("separate target grant does not approve the target")
        evidence["controls"].append(
            measured(
                "legitimate_target",
                adapter.call_with_separate_target_grant,
                control_grant=separate_grant,
            )
        )

    evidence["run"]["http_requests"] = adapter.http_requests
    verdict = evaluate(evidence)
    return evidence, verdict
