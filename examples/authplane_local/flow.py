"""Local OAuth consent, token, grant and effect calls for the example adapter.

Credentials stay in the disposable setup JSON and process memory. Only the
collector's validated, redacted evidence is written to disk.
"""

import base64
import hashlib
import html
import json
import os
import re
import secrets
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import requests


TEMP = Path(
    os.environ.get("GRANT_EFFECT_AUTHPLANE_TEMP", "/tmp/grant-effect-authplane-v023")
)
SETUP = json.loads((TEMP / "setup.json").read_text())
CONFIG = (TEMP / "config.yaml").read_text()
ADMIN_KEY = re.search(r"^  api_key: (.+)$", CONFIG, re.M).group(1)
AS = "http://127.0.0.1:18750"
ADMIN = "http://127.0.0.1:18751"
REDIRECT = "http://127.0.0.1:18762/callback"
SCOPE = "test:effect"
MAX_REQUESTS = 60
events = []
last_grant_id = None


def label(uri):
    return {SETUP["uri_a"]: "A", SETUP["uri_b"]: "B"}.get(uri, "unknown")


def call(method, url, *, session=None, step, **kw):
    if len(events) >= MAX_REQUESTS:
        raise RuntimeError("frozen HTTP request budget exceeded")
    client = session or requests
    response = client.request(method, url, allow_redirects=False, timeout=8, **kw)
    data = kw.get("data") or kw.get("params") or {}
    events.append(
        {
            "step": step,
            "method": method,
            "path": urlparse(url).path,
            "resource": (
                label(data.get("resource"))
                if isinstance(data, dict) and "resource" in data
                else None
            ),
            "status": response.status_code,
        }
    )
    return response


def admin_call(method, path, *, step):
    response = call(
        method,
        ADMIN + path,
        step=step,
        headers={"Authorization": "Bearer " + ADMIN_KEY},
    )
    assert response.status_code in (200, 204), (
        path,
        response.status_code,
        response.text[:200],
    )
    return response


def grant_list():
    uid = SETUP["test_user"]["id"]
    return admin_call("GET", f"/admin/users/{uid}/grants", step="grant_record").json()[
        "consent_grants"
    ]


def clear_grant():
    global last_grant_id
    if last_grant_id is None:
        active = [g for g in grant_list() if not g.get("revoked_at")]
        assert len(active) <= 1, active
        last_grant_id = active[0]["id"] if active else None
    if last_grant_id:
        admin_call(
            "DELETE",
            f"/admin/grants/consent/{last_grant_id}",
            step="revoke_previous_grant",
        )
    last_grant_id = None


def hidden(body, name):
    found = re.search(
        r'<input[^>]*name="' + re.escape(name) + r'"[^>]*value="([^"]*)"', body
    )
    assert found, f"missing form field {name}"
    return html.unescape(found.group(1))


def authorize_and_exchange(trial, authorize_uri, exchange_uri):
    global last_grant_id
    clear_grant()
    session = requests.Session()
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    state = secrets.token_urlsafe(12)
    query = {
        "response_type": "code",
        "client_id": SETUP["client"]["client_id"],
        "redirect_uri": REDIRECT,
        "scope": SCOPE,
        "resource": authorize_uri,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    r = call(
        "GET",
        AS + "/oauth/authorize",
        session=session,
        step=trial + ":authorize",
        params=query,
    )
    saw_consent = False
    consent_target = None
    callback = None
    for _ in range(8):
        location = r.headers.get("Location")
        if location and location.startswith(REDIRECT):
            callback = location
            break
        if r.status_code == 303 and location:
            r = call(
                "GET", urljoin(AS, location), session=session, step=trial + ":follow"
            )
            continue
        if r.status_code == 200 and urlparse(r.url).path == "/login":
            r = call(
                "POST",
                AS + "/login",
                session=session,
                step=trial + ":login",
                data={
                    "csrf_token": hidden(r.text, "csrf_token"),
                    "redirect": hidden(r.text, "redirect"),
                    "email": SETUP["test_user"]["email"],
                    "password": SETUP["test_password"],
                },
            )
            continue
        if r.status_code == 200 and urlparse(r.url).path == "/consent":
            saw_consent = True
            consent_target = (
                "A"
                if "Heldout A" in r.text
                else "B" if "Heldout B" in r.text else "unknown"
            )
            r = call(
                "POST",
                AS + "/consent",
                session=session,
                step=trial + ":consent",
                data={
                    "session_id": hidden(r.text, "session_id"),
                    "csrf_token": hidden(r.text, "csrf_token"),
                    "scopes": SCOPE,
                    "action": "allow",
                },
            )
            continue
        raise RuntimeError(
            f"unexpected OAuth step {r.status_code} {urlparse(r.url).path} {r.text[:160]}"
        )
    assert callback is not None, "no authorization callback"
    params = parse_qs(urlparse(callback).query)
    assert params.get("state") == [state], "state mismatch"
    grants = [g for g in grant_list() if not g.get("revoked_at")]
    assert len(grants) == 1, grants
    grant = grants[0]
    last_grant_id = grant["id"]
    granted_resource = (
        "A"
        if grant["resource_id"] == SETUP["a"]["id"]
        else "B" if grant["resource_id"] == SETUP["b"]["id"] else "unknown"
    )
    r = call(
        "POST",
        AS + "/oauth/token",
        session=session,
        step=trial + ":exchange",
        data={
            "grant_type": "authorization_code",
            "code": params["code"][0],
            "redirect_uri": REDIRECT,
            "client_id": SETUP["client"]["client_id"],
            "code_verifier": verifier,
            "resource": exchange_uri,
        },
    )
    result = {
        "trial": trial,
        "authorize": label(authorize_uri),
        "exchange": label(exchange_uri),
        "consent_screen_seen": saw_consent,
        "consent_screen_target": consent_target,
        "recorded_grant_resource": granted_resource,
        "recorded_grant_scopes": grant["scopes"],
        "exchange_status": r.status_code,
    }
    if r.ok:
        token = r.json()
        result["refresh_issued"] = bool(token.get("refresh_token"))
    else:
        token = None
        result["exchange_error"] = r.json().get("error")
    return result, token


def effect(token, target, *, trial):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    r = call(
        "POST",
        SETUP["uri_a" if target == "A" else "uri_b"],
        step=trial + ":effect:" + target,
        headers=headers,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "write_effect", "arguments": {}},
        },
    )
    return {
        "status": r.status_code,
        "effect_count": r.json().get("result", {}).get("effect_count"),
    }


def refresh(trial, token, target):
    r = call(
        "POST",
        AS + "/oauth/token",
        step=trial + ":refresh",
        data={
            "grant_type": "refresh_token",
            "refresh_token": token["refresh_token"],
            "client_id": SETUP["client"]["client_id"],
            "resource": SETUP["uri_a" if target == "A" else "uri_b"],
        },
    )
    result = {"status": r.status_code}
    if r.ok:
        return result, r.json()
    result["error"] = r.json().get("error")
    return result, None
