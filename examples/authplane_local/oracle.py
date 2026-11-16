import asyncio, json, os, sys
from pathlib import Path
from authplane import AuthplaneClient
from authplane.errors import AuthplaneError

p = Path(
    os.environ.get("GRANT_EFFECT_AUTHPLANE_TEMP", "/tmp/grant-effect-authplane-v023")
)
d = json.loads((p / "setup.json").read_text())
ISS = "http://127.0.0.1:18750"
counts = {"A": 0, "B": 0}


async def handle(reader, writer, which, resource):
    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
        lines = head.decode("latin1").split("\r\n")
        method, path, _ = lines[0].split(" ", 2)
        hdr = {
            k.lower(): v.strip()
            for line in lines[1:]
            if ":" in line
            for k, v in [line.split(":", 1)]
        }
        n = int(hdr.get("content-length", "0"))
        body = await asyncio.wait_for(reader.readexactly(n), timeout=5) if n else b""
        status = 404
        obj = {"error": "not_found"}
        if method == "GET" and path == "/state":
            status = 200
            obj = {"count": counts[which]}
        elif method == "POST" and path == "/mcp":
            bearer = hdr.get("authorization", "")
            if not bearer.startswith("Bearer "):
                status = 401
                obj = {"error": "missing_token"}
            else:
                try:
                    claims = await resource.verify(bearer[7:])
                    rpc = json.loads(body)
                    rpc_method = rpc.get("method")
                    if rpc_method == "initialize":
                        status = 200
                        obj = {
                            "jsonrpc": "2.0",
                            "id": rpc.get("id"),
                            "result": {
                                "protocolVersion": "2025-11-25",
                                "capabilities": {"tools": {}},
                                "serverInfo": {
                                    "name": "heldout-effect-oracle",
                                    "version": "1",
                                },
                            },
                        }
                    elif rpc_method == "tools/list":
                        status = 200
                        obj = {
                            "jsonrpc": "2.0",
                            "id": rpc.get("id"),
                            "result": {
                                "tools": [
                                    {
                                        "name": "write_effect",
                                        "description": "Write one local state effect",
                                        "inputSchema": {
                                            "type": "object",
                                            "properties": {},
                                        },
                                    }
                                ]
                            },
                        }
                    elif (
                        rpc_method == "tools/call"
                        and rpc.get("params", {}).get("name") == "write_effect"
                        and "test:effect" in claims.scopes
                    ):
                        counts[which] += 1
                        status = 200
                        obj = {
                            "jsonrpc": "2.0",
                            "id": rpc.get("id"),
                            "result": {
                                "content": [{"type": "text", "text": "ok"}],
                                "effect_count": counts[which],
                            },
                        }
                    else:
                        status = 403
                        obj = {"error": "invalid_tool_or_scope"}
                except (AuthplaneError, ValueError) as e:
                    status = 401
                    obj = {"error": type(e).__name__}
        payload = json.dumps(obj).encode()
        reason = {200: "OK", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found"}[
            status
        ]
        writer.write(
            f"HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode()
            + payload
        )
        await writer.drain()
    except Exception as e:
        print("oracle_error", which, type(e).__name__, str(e)[:120], file=sys.stderr)
    finally:
        writer.close()
        await writer.wait_closed()


async def main():
    client = await AuthplaneClient.create(ISS, dev_mode=True)
    ra = client.resource(d["uri_a"], scopes=["test:effect"])
    rb = client.resource(d["uri_b"], scopes=["test:effect"])
    sa = await asyncio.start_server(
        lambda r, w: handle(r, w, "A", ra), "127.0.0.1", 18760
    )
    sb = await asyncio.start_server(
        lambda r, w: handle(r, w, "B", rb), "127.0.0.1", 18761
    )
    print("ready official-sdk protected effect oracles A/B", flush=True)
    try:
        await asyncio.gather(sa.serve_forever(), sb.serve_forever())
    finally:
        await client.aclose()


asyncio.run(main())
