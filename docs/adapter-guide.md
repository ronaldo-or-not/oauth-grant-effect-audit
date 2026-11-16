# Writing a collector adapter

`grant-effect-collect` loads a **trusted local Python file** containing `create_adapter()`. Loading the file executes its code with the current user's permissions, so only use an adapter you wrote or reviewed. The runner calls its methods in this order:

1. `observe_grant()` obtains the original approved resource set from a server grant record or an explicit consent UI resource list.
2. `read_effect(B)`, `call_anonymous(B)`, `read_effect(B)` measure an unauthenticated control.
3. `read_effect(B)`, `call_with_approved_token(B)`, `read_effect(B)` measure the original grant's A token at B.
4. `read_effect(B)`, `call_candidate(B)`, `read_effect(B)` measure the transition under test.
5. Only when step 4 has zero effect: `observe_separate_target_grant(B)` and a measured `call_with_separate_target_grant(B)` prove that B is reachable with proper authorization.

The adapter implements the `Adapter` protocol in `src/grant_effect_audit/collector.py` and returns `GrantSnapshot`, `EffectSnapshot` and `CallResult`. Each `EffectSnapshot` needs a unique reference for its independent server read. Use monotonic effect counts. The adapter's `http_requests` includes setup, consent, effect reads and calls if those requests occurred during this collection run.

Tokens, passwords and cookies remain **inside the adapter**. The returned grant and effect snapshots must contain no secret values. The collector calls the existing evidence checker before writing output, rejects common secret-bearing fields, writes the result with mode `0600`, and refuses to overwrite an existing file.

The runner requires an isolation attestation and a loopback target by default. `--allow-non-loopback` only removes the URI check; it does not grant permission to test a remote service. The operator remains responsible for authorization, rate limits, the correctness of the independent effect oracle, and cleanup of effectful test data. A service adapter should fail closed if its grant record, token flow, or effect counter does not match its expected fixture.

The [AuthPlane local example](../examples/authplane_local/README.md) shows a complete adapter with real OAuth consent, refresh and SDK-protected HTTP effect calls. Its target is an isolated synthetic account and two loopback resource servers.
