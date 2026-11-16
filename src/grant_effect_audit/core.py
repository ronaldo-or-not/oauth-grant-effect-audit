"""Classify a recorded OAuth resource-boundary experiment.

The module never sends network requests or treats a token response as an
independent proof of a protected operation. Evidence authenticity remains the
responsibility of the experimenter who captured the consent and server state.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit


class EvidenceError(ValueError):
    """The evidence file is malformed or contains a secret-bearing field."""


_SECRET_KEYS = {
    "access_token", "refresh_token", "id_token", "client_secret", "password",
    "cookie", "authorization_header", "api_key", "private_key",
}
_GRANT_SOURCES = {"server_grant_record", "consent_ui_resource_list"}
_EFFECT_SOURCES = {"server_counter", "server_database", "server_audit_log"}
_CONTROL_KINDS = {"anonymous", "approved_token", "legitimate_target"}


@dataclass(frozen=True)
class Verdict:
    case_id: str
    status: str
    reasons: tuple[str, ...]
    target_resource: str
    effect_delta: int | None
    http_requests: int | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must be an object")
    return value


def _text(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise EvidenceError(f"{path} must be a nonempty string")
    return value


def _resource(value: Any, path: str) -> str:
    uri = _text(value, path)
    parts = urlsplit(uri)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise EvidenceError(f"{path} must be an absolute HTTP(S) URI")
    if parts.username or parts.password or parts.fragment:
        raise EvidenceError(f"{path} must not contain credentials or a fragment")
    return uri


def _nonnegative_int(value: Any, path: str) -> int:
    if type(value) is not int or value < 0:
        raise EvidenceError(f"{path} must be a nonnegative integer")
    return value


def _scan_for_secrets(value: Any, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise EvidenceError(f"{path} contains a non-string key")
            if key.lower() in _SECRET_KEYS:
                raise EvidenceError(f"{path}.{key} is a secret-bearing field; remove it")
            _scan_for_secrets(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_for_secrets(child, f"{path}[{index}]")
    elif isinstance(value, str) and ("Bearer " in value or value.count(".") == 2 and value.startswith("eyJ")):
        raise EvidenceError(f"{path} appears to contain a bearer token")


def _effect(record: Mapping[str, Any], path: str) -> tuple[int, str, str]:
    effect = _object(record.get("effect"), f"{path}.effect")
    before = _nonnegative_int(effect.get("before"), f"{path}.effect.before")
    after = _nonnegative_int(effect.get("after"), f"{path}.effect.after")
    if after < before:
        raise EvidenceError(f"{path}.effect counters must be monotonic")
    source = _text(effect.get("source_kind"), f"{path}.effect.source_kind")
    reference = _text(effect.get("reference"), f"{path}.effect.reference")
    return after - before, source, reference


def evaluate(raw: Mapping[str, Any]) -> Verdict:
    """Return a bounded verdict for one recorded, isolated experiment.

    A finding requires an independent grant observation, independent server
    effect evidence, a clean anonymous control and a clean A-token-at-B
    control. A zero-effect verdict additionally requires a working, separately
    authorized B control so a broken target is not mistaken for a defense.
    """
    evidence = _object(raw, "evidence")
    _scan_for_secrets(evidence)
    if evidence.get("schema_version") != "1":
        raise EvidenceError("schema_version must be '1'")
    case_id = _text(evidence.get("case_id"), "case_id")
    run = _object(evidence.get("run"), "run")
    isolated = run.get("isolated")
    if type(isolated) is not bool:
        raise EvidenceError("run.isolated must be a boolean")
    request_count = run.get("http_requests")
    if request_count is not None:
        request_count = _nonnegative_int(request_count, "run.http_requests")

    grant = _object(evidence.get("grant"), "grant")
    grant_ref = _text(grant.get("reference"), "grant.reference")
    grant_source = _text(grant.get("source_kind"), "grant.source_kind")
    approved = grant.get("approved_resources")
    if not isinstance(approved, list) or not approved:
        raise EvidenceError("grant.approved_resources must be a nonempty list")
    approved_resources = {
        _resource(uri, f"grant.approved_resources[{index}]")
        for index, uri in enumerate(approved)
    }
    if len(approved_resources) != len(approved):
        raise EvidenceError("grant.approved_resources contains duplicates")
    target = _resource(evidence.get("target_resource"), "target_resource")

    candidate = _object(evidence.get("candidate"), "candidate")
    if _text(candidate.get("grant_reference"), "candidate.grant_reference") != grant_ref:
        raise EvidenceError("candidate.grant_reference differs from grant.reference")
    if _resource(candidate.get("target_resource"), "candidate.target_resource") != target:
        raise EvidenceError("candidate.target_resource differs from target_resource")
    _text(candidate.get("transition"), "candidate.transition")
    candidate_delta, candidate_source, candidate_effect_ref = _effect(candidate, "candidate")

    controls_raw = evidence.get("controls")
    if not isinstance(controls_raw, list):
        raise EvidenceError("controls must be a list")
    controls: dict[str, tuple[int, str, str]] = {}
    effect_refs = {candidate_effect_ref}
    for index, item in enumerate(controls_raw):
        control = _object(item, f"controls[{index}]")
        kind = _text(control.get("kind"), f"controls[{index}].kind")
        if kind not in _CONTROL_KINDS or kind in controls:
            raise EvidenceError(f"controls[{index}].kind is unknown or duplicated")
        if _resource(control.get("target_resource"), f"controls[{index}].target_resource") != target:
            raise EvidenceError(f"controls[{index}] targets a different resource")
        if kind == "approved_token":
            if control.get("grant_reference") != grant_ref:
                raise EvidenceError("approved_token control must use the candidate grant")
        if kind == "legitimate_target":
            control_grant = _text(control.get("grant_reference"), f"controls[{index}].grant_reference")
            if control_grant == grant_ref:
                raise EvidenceError("legitimate_target control needs a separate grant")
            control_approved = control.get("approved_resources")
            if not isinstance(control_approved, list) or target not in control_approved:
                raise EvidenceError("legitimate_target control must list the target in its separate grant")
            for resource_index, resource in enumerate(control_approved):
                _resource(resource, f"controls[{index}].approved_resources[{resource_index}]")
        observed = _effect(control, f"controls[{index}]")
        if observed[2] in effect_refs:
            raise EvidenceError("effect references must identify distinct measurement intervals")
        effect_refs.add(observed[2])
        controls[kind] = observed

    def result(status: str, *reasons: str) -> Verdict:
        return Verdict(case_id, status, tuple(reasons), target, candidate_delta, request_count)

    gaps: list[str] = []
    if not isolated:
        gaps.append("run_not_isolated")
    if grant_source not in _GRANT_SOURCES:
        gaps.append("grant_not_independently_observed")
    if gaps:
        return result("inconclusive", *gaps)
    if target in approved_resources:
        return result("within_grant", "target_is_approved")
    if candidate_source not in _EFFECT_SOURCES:
        gaps.append("candidate_effect_not_server_observed")
    for required in ("anonymous", "approved_token"):
        if required not in controls:
            gaps.append(f"missing_{required}_control")
        else:
            delta, source, _reference = controls[required]
            if source not in _EFFECT_SOURCES:
                gaps.append(f"{required}_effect_not_server_observed")
            if delta != 0:
                gaps.append(f"{required}_control_changed_target")
    if gaps:
        return result("inconclusive", *gaps)
    if candidate_delta > 0:
        return result("out_of_grant_effect_observed", "server_effect_after_unapproved_transition")

    legitimate = controls.get("legitimate_target")
    if legitimate is None:
        return result("inconclusive", "missing_legitimate_target_control")
    legitimate_delta, legitimate_source, _reference = legitimate
    if legitimate_source not in _EFFECT_SOURCES or legitimate_delta <= 0:
        return result("inconclusive", "target_reachability_not_demonstrated")
    return result("no_out_of_grant_effect_observed", "target_reachable_with_separate_authorization")
