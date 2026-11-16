# Evidence format v1

One JSON file describes **one** grant-to-target experiment. Use the sample files in `examples/` as templates. The checker makes no network requests.

| Field | Meaning |
| --- | --- |
| `schema_version` | Literal string `"1"` |
| `case_id` | Local, non-sensitive experiment identifier |
| `run.isolated` | `true` only when the measured effect can be attributed to this run rather than concurrent users or tests |
| `run.http_requests` | Optional total HTTP request count, including setup and controls if those were measured together |
| `grant.reference` | Stable local reference to the original grant; repeat it in the candidate and approved-token control |
| `grant.source_kind` | `server_grant_record` or `consent_ui_resource_list` for an independently observed approved resource list; other values make the result inconclusive |
| `grant.approved_resources` | Full set of canonical resource URIs approved under this grant, not just the resource requested for one access token |
| `target_resource` | Canonical URI of the resource whose effect is under test |
| `controls` | Recorded calls to the target, as described below |
| `candidate.transition` | Human-readable name of the state transition being evaluated; no vendor-specific code is required |
| `candidate.grant_reference` | Must match `grant.reference` |
| `candidate.target_resource` | Must match the top-level target |
| `candidate.effect` | Before/after monotonic server effect counter plus declared provenance |

Control kinds:

| `kind` | Required? | Expected observation |
| --- | --- | --- |
| `anonymous` | Yes | No target effect without credentials |
| `approved_token` | Yes | No target effect when using the original grant's resource-A token at B; `grant_reference` must match |
| `legitimate_target` | For zero-effect verdict | Positive effect with a **separately authorized** B grant, ideally in a fresh isolated fixture. Include a different `grant_reference` and an `approved_resources` list containing B. |

Each control and candidate contains an `effect` object:

```json
{
  "before": 0,
  "after": 1,
  "source_kind": "server_database",
  "reference": "private-fixture-export-7"
}
```

`before` and `after` are nonnegative, monotonic **effect counters**, not account balances or arbitrary values that can decrease. Give each measurement interval a distinct `reference`. Independent source kinds are `server_counter`, `server_database` and `server_audit_log`. A client response is useful context but cannot stand in for an independent effect witness. Optional `http_status` fields are recorded for a reviewer; the verdict uses the effect delta because a failed HTTP response can still follow a committed effect and a successful response can be empty.

The checker rejects raw fields named `access_token`, `refresh_token`, `id_token`, `client_secret`, `password`, `cookie`, `authorization_header`, `api_key` and `private_key`, as well as obvious bearer token strings. This is a guardrail, **not** comprehensive secret detection. Keep source evidence private and review any file before publishing it.

## Interpretation

- `out_of_grant_effect_observed`: B is outside the recorded full grant; independent B effect increased after the candidate; required controls remained at zero; the run was isolated.
- `no_out_of_grant_effect_observed`: same controls and independent measurement, candidate effect zero, and a separate legitimate B control demonstrated reachability. This says nothing about untested transitions.
- `within_grant`: B is already in the recorded grant. A B effect cannot, on this evidence alone, be called an out-of-grant effect.
- `inconclusive`: missing provenance, controls, isolation, or target reachability. Inspect `reasons`.

URI comparison is exact. Collectors should use the canonical resource identifier accepted by the service and keep its representation consistent. Different spelling of the same resource should not be counted as two resources.
