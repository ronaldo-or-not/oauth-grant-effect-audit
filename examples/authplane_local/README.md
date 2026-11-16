# AuthPlane v0.2.3 local collection example

This example runs the collector against the [official AuthPlane authserver v0.2.3 release](https://github.com/AuthPlane/authserver/releases/tag/v0.2.3) and two local MCP-style resource servers protected by the [official AuthPlane Python SDK](https://github.com/authplane/python-sdk). Everything binds to `127.0.0.1`; the account, workflows and effects are synthetic.

The adapter obtains a fresh A-only consent, reads the actual server grant record, measures B's server-side effect counter around anonymous and A-token controls, requests B during refresh, and then obtains a separate B consent to prove that B works normally. Tokens stay in the temporary setup file or process memory. The output contains no token, password or cookie.

## Setup on macOS arm64

Use Python 3.12 or newer. Run these commands from the repository root. The archive URL is for macOS arm64; for other platforms choose the corresponding asset on the official release page and verify its published checksum.

```sh
export GRANT_EFFECT_AUTHPLANE_TEMP=/tmp/grant-effect-authplane-v023
mkdir -p "$GRANT_EFFECT_AUTHPLANE_TEMP"
curl -fsSL https://github.com/AuthPlane/authserver/releases/download/v0.2.3/authserver_0.2.3_darwin_arm64.tar.gz -o "$GRANT_EFFECT_AUTHPLANE_TEMP/authserver_0.2.3_darwin_arm64.tar.gz"
curl -fsSL https://github.com/AuthPlane/authserver/releases/download/v0.2.3/checksums.txt -o "$GRANT_EFFECT_AUTHPLANE_TEMP/checksums.txt"
python3.12 -c 'import hashlib,os,pathlib; p=pathlib.Path(os.environ["GRANT_EFFECT_AUTHPLANE_TEMP"])/"authserver_0.2.3_darwin_arm64.tar.gz"; actual=hashlib.sha256(p.read_bytes()).hexdigest(); assert actual=="5421ebb31a448f76683cf062debc1075640f225e365a0217d032e5136655df60"; print("official archive checksum verified")'
tar -xzf "$GRANT_EFFECT_AUTHPLANE_TEMP/authserver_0.2.3_darwin_arm64.tar.gz" -C "$GRANT_EFFECT_AUTHPLANE_TEMP"
python3.12 -m venv "$GRANT_EFFECT_AUTHPLANE_TEMP/venv"
"$GRANT_EFFECT_AUTHPLANE_TEMP/venv/bin/pip" install -e . requests 'authplane-sdk==0.5.0'
"$GRANT_EFFECT_AUTHPLANE_TEMP/venv/bin/python" examples/authplane_local/setup.py prepare
```

Start the official server in one terminal, always passing the generated configuration:

```sh
export GRANT_EFFECT_AUTHPLANE_TEMP=/tmp/grant-effect-authplane-v023
"$GRANT_EFFECT_AUTHPLANE_TEMP/authserver" serve --config "$GRANT_EFFECT_AUTHPLANE_TEMP/config.yaml"
```

In another terminal, provision the disposable A/B resources and start the SDK-protected effect servers:

```sh
export GRANT_EFFECT_AUTHPLANE_TEMP=/tmp/grant-effect-authplane-v023
"$GRANT_EFFECT_AUTHPLANE_TEMP/venv/bin/python" examples/authplane_local/setup.py provision
"$GRANT_EFFECT_AUTHPLANE_TEMP/venv/bin/python" examples/authplane_local/oracle.py
```

Run the collector in a third terminal. The output file must not already exist:

```sh
export GRANT_EFFECT_AUTHPLANE_TEMP=/tmp/grant-effect-authplane-v023
"$GRANT_EFFECT_AUTHPLANE_TEMP/venv/bin/grant-effect-collect" \
  --adapter examples/authplane_local/adapter.py \
  --output "$GRANT_EFFECT_AUTHPLANE_TEMP/evidence.json" \
  --case-id authplane-v023-local-B \
  --target http://127.0.0.1:18761/mcp \
  --transition refresh-resource-change
"$GRANT_EFFECT_AUTHPLANE_TEMP/venv/bin/grant-effect-audit" "$GRANT_EFFECT_AUTHPLANE_TEMP/evidence.json" --json
```

Expected on the tested fixed release: anonymous B and A-token-at-B requests return 401 without an effect; a B-resource refresh of an A-only grant returns 400 without an effect; a separate B authorization executes B once. This yields `no_out_of_grant_effect_observed` for this one transition. It does not certify every AuthPlane configuration or authorization path.

Our fresh local run on 2026-11-16 recorded 32 HTTP requests and the same result in [observed-v023.json](observed-v023.json). The grant IDs in that file belong only to the disposable synthetic instance. The release archive SHA-256 matched both the value above and the release's `checksums.txt`.

The local effect server's counter is a test oracle, not a production MCP integration. The authorization server and SDK token validation are unmodified official releases. Keep the temporary directory private; it contains live synthetic credentials. Stop the processes and remove the disposable directory after use.
