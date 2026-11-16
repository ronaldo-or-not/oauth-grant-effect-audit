"""Provision the official local AuthPlane release for an A/B audit example.

Run `prepare` before starting authserver, then `provision` after readiness.
Only disposable loopback ports and synthetic data are used. Temporary secrets
stay in the disposable GRANT_EFFECT_AUTHPLANE_TEMP directory with mode 0600.
"""

import argparse
import json
import os
import re
import secrets
import urllib.error
import urllib.request
from pathlib import Path


TEMP = Path(
    os.environ.get("GRANT_EFFECT_AUTHPLANE_TEMP", "/tmp/grant-effect-authplane-v023")
)
AS = "http://127.0.0.1:18750"
ADMIN = "http://127.0.0.1:18751"
A = "http://127.0.0.1:18760/mcp"
B = "http://127.0.0.1:18761/mcp"


def private_write(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write(data)


def prepare():
    TEMP.mkdir(parents=True, exist_ok=True)
    (TEMP / "instance" / "keys").mkdir(parents=True, exist_ok=True)
    config = TEMP / "config.yaml"
    if config.exists():
        raise SystemExit(f"refusing to replace existing {config}")
    private_write(
        config,
        (
            "server:\n  address: 127.0.0.1:18750\n  issuer: " + AS + "\n"
            "admin:\n  address: 127.0.0.1:18751\n  api_key: "
            + secrets.token_hex(32)
            + "\n"
            "session:\n  secret: " + secrets.token_hex(32) + "\n"
            "storage:\n  sqlite:\n    path: "
            + str(TEMP / "instance" / "authserver.db")
            + "\n"
            "signing:\n  key_path: " + str(TEMP / "instance" / "keys") + "\n"
        ),
    )
    print("prepared disposable loopback configuration")


def provision():
    output = TEMP / "setup.json"
    if output.exists():
        raise SystemExit(f"refusing to replace existing {output}")
    key = re.search(
        r"^  api_key: (.+)$", (TEMP / "config.yaml").read_text(), re.M
    ).group(1)
    headers = {"Authorization": "Bearer " + key, "Content-Type": "application/json"}

    def post(path, body):
        request = urllib.request.Request(
            ADMIN + path, method="POST", headers=headers, data=json.dumps(body).encode()
        )
        try:
            with urllib.request.urlopen(request, timeout=8) as response:
                assert response.status == 201
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError(
                f"{path} returned HTTP {error.code}: {error.read().decode()[:200]}"
            ) from error

    resource_a = post(
        "/admin/resources",
        {
            "slug": "heldout-a",
            "display_name": "Heldout A",
            "backend_kind": "mint",
            "uri": A,
            "scopes": [{"name": "test:effect", "description": "Local effect oracle"}],
        },
    )
    resource_b = post(
        "/admin/resources",
        {
            "slug": "heldout-b",
            "display_name": "Heldout B",
            "backend_kind": "mint",
            "uri": B,
            "scopes": [{"name": "test:effect", "description": "Local effect oracle"}],
        },
    )
    client = post(
        "/admin/clients",
        {
            "client_name": "heldout-client",
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "none",
            "redirect_uris": ["http://127.0.0.1:18762/callback"],
            "scope": "test:effect",
        },
    )
    password = secrets.token_urlsafe(20)
    user = post(
        "/admin/users",
        {
            "email": "heldout@example.invalid",
            "password": password,
            "name": "Heldout",
            "role": "user",
        },
    )
    private_write(
        output,
        json.dumps(
            {
                "a": resource_a,
                "b": resource_b,
                "client": client,
                "test_user": user,
                "test_password": password,
                "uri_a": A,
                "uri_b": B,
            }
        ),
    )
    print("provisioned A/B resources, one client and one synthetic user")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=["prepare", "provision"])
    args = parser.parse_args()
    {"prepare": prepare, "provision": provision}[args.phase]()
