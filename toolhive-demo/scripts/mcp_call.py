#!/usr/bin/env python3
"""Minimal MCP (streamable HTTP) client, standard library only.

Used by demo.sh to talk to ToolHive the same way Claude Code does, but
scriptable, so the demo can be verified without an agent.

    mcp_call.py URL TOKEN tools
    mcp_call.py URL TOKEN call TOOL '{"arg": "value"}'

Exit codes: 0 success, 3 denied by policy (HTTP 403 or JSON-RPC error that
says so), 4 unauthenticated (401), 1 anything else.
"""

from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request

PROTOCOL = "2025-06-18"


class MCPError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class Client:
    def __init__(self, url: str, token: str):
        self.url = url.split("#", 1)[0]
        self.token = token
        self.session: str | None = None
        self._id = 0

    def _post(self, payload: dict) -> dict | None:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": PROTOCOL,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        req = urllib.request.Request(self.url, data=json.dumps(payload).encode(), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                self.session = resp.headers.get("Mcp-Session-Id") or self.session
                body = resp.read().decode()
                ctype = resp.headers.get("Content-Type", "")
        except urllib.error.HTTPError as e:
            raise MCPError(e.code, e.read().decode(errors="replace").strip() or e.reason) from None
        if "id" not in payload or not body.strip():
            return None
        if "text/event-stream" in ctype:
            # Take the last JSON-RPC message that answers our id.
            msg = None
            for line in body.splitlines():
                if line.startswith("data:"):
                    data = line[5:].strip()
                    if data:
                        cand = json.loads(data)
                        if cand.get("id") == payload["id"]:
                            msg = cand
            if msg is None:
                raise MCPError(0, f"no response in event stream: {body[:200]}")
            return msg
        return json.loads(body)

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        msg = self._post({"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}})
        if msg is None:
            raise MCPError(0, "empty response")
        if "error" in msg:
            raise MCPError(200, json.dumps(msg["error"]))
        return msg["result"]

    def initialize(self) -> None:
        self.request(
            "initialize",
            {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "toolhive-demo-cli", "version": "1.0"}},
        )
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})


def looks_denied(e: MCPError) -> bool:
    text = str(e).lower()
    return e.status == 403 or "unauthorized" in text or "forbidden" in text or "not authorized" in text or "denied" in text


def main(argv: list[str]) -> int:
    if len(argv) < 4 or argv[3] not in {"tools", "call"}:
        print(__doc__, file=sys.stderr)
        return 2
    url, token, cmd = argv[1], argv[2], argv[3]
    c = Client(url, token)
    try:
        c.initialize()
        if cmd == "tools":
            tools = c.request("tools/list")["tools"]
            print(json.dumps(sorted(t["name"] for t in tools)))
            return 0
        tool = argv[4]
        args = json.loads(argv[5]) if len(argv) > 5 else {}
        result = c.request("tools/call", {"name": tool, "arguments": args})
        texts = [b.get("text", "") for b in result.get("content", []) if b.get("type") == "text"]
        print("\n".join(texts) if texts else json.dumps(result))
        return 1 if result.get("isError") else 0
    except MCPError as e:
        if e.status == 401:
            print(f"401 Unauthenticated: {e}", file=sys.stderr)
            return 4
        if looks_denied(e):
            print(f"DENIED ({e.status}): {e}", file=sys.stderr)
            return 3
        print(f"error ({e.status}): {e}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError) as e:
        print(f"connection failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
