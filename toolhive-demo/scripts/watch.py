#!/usr/bin/env python3
"""Live decision feed: follows the PDP decision log and ToolHive's audit logs.

    watch.py STATE_DIR            # both
    watch.py STATE_DIR pdp        # only PDP decisions (why)
    watch.py STATE_DIR pep        # only ToolHive audit events (what was enforced)

PDP lines answer "what did the policy decide, and which policy decided it".
PEP lines answer "what did ToolHive actually let through to the MCP server".
"""

from __future__ import annotations

import glob
import json
import os
import sys
import time

RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"
GREEN, RED, YELLOW, CYAN, MAGENTA = "\033[32m", "\033[31m", "\033[33m", "\033[36m", "\033[35m"
NOISY_ROLES = ("default-roles-", "offline_access", "uma_authorization")


def hhmmss(ts: str) -> str:
    return ts[11:19] if len(ts) >= 19 else ts


def fmt_pdp(e: dict) -> str:
    allow = e.get("decision") == "allow"
    verdict = f"{BOLD}{GREEN}ALLOW{RESET}" if allow else f"{BOLD}{RED}DENY {RESET}"
    p = e.get("principal", {})
    who = p.get("username") or (p.get("sub") or "?")[:8]
    roles = ",".join(r for r in p.get("roles") or [] if not r.startswith(NOISY_ROLES)) or "-"
    r = e.get("resource", {})
    phase = "list?" if not e.get("args") else "call"
    line = (
        f"{DIM}{hhmmss(e.get('time', ''))}{RESET} {CYAN}[PDP]{RESET} {verdict} "
        f"{who:<12} {DIM}[{roles}]{RESET} {r.get('name', '?')}@{r.get('server', '?')} "
        f"{DIM}({phase}) ← {e.get('reason', '')}{RESET}"
    )
    if e.get("args"):
        args = json.dumps(e["args"], separators=(",", ":"))
        line += f"\n{' ' * 15}{DIM}args {args[:160]}{RESET}"
    return line


def fmt_audit(e: dict) -> str | None:
    etype = e.get("type", "")
    if etype in ("mcp_ping", "mcp_notification", "sse_connection"):
        return None
    outcome = e.get("outcome", "?")
    color = {"success": GREEN, "denied": RED, "failure": YELLOW, "error": YELLOW}.get(outcome, "")
    s = e.get("subjects") or {}
    who = s.get("user") or (s.get("user_id") or "anonymous")[:12]
    t = e.get("target") or {}
    what = t.get("name") or t.get("method") or t.get("endpoint") or ""
    extra = (e.get("metadata") or {}).get("extra") or {}
    dur = extra.get("duration_ms")
    dur_s = f" {dur}ms" if dur is not None else ""
    return (
        f"{DIM}{hhmmss(e.get('logged_at', ''))}{RESET} {MAGENTA}[PEP]{RESET} "
        f"{color}{BOLD}{outcome.upper():<7}{RESET} {who:<12} {etype:<16} {what} "
        f"{DIM}via {e.get('component', '?')}{dur_s}{RESET}"
    )


def follow(state: str, which: str) -> None:
    patterns = []
    if which in ("all", "pdp"):
        patterns.append(os.path.join(state, "decisions.jsonl"))
    if which in ("all", "pep"):
        patterns.append(os.path.join(state, "audit-*.jsonl"))

    offsets: dict[str, int] = {}
    # Start at the end of existing files: show only new activity.
    for pat in patterns:
        for f in glob.glob(pat):
            offsets[f] = os.path.getsize(f)

    print(f"{DIM}watching {', '.join(patterns)}  (Ctrl-C to stop){RESET}", flush=True)
    while True:
        for pat in patterns:
            for f in sorted(glob.glob(pat)):
                pos = offsets.get(f, 0)
                size = os.path.getsize(f)
                if size < pos:
                    pos = 0
                if size == pos:
                    continue
                with open(f, encoding="utf-8", errors="replace") as fh:
                    fh.seek(pos)
                    chunk = fh.read()
                    offsets[f] = fh.tell()
                for raw in chunk.splitlines():
                    raw = raw.strip()
                    if not raw:
                        continue
                    try:
                        e = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    out = fmt_pdp(e) if f.endswith("decisions.jsonl") else fmt_audit(e)
                    if out:
                        print(out, flush=True)
        time.sleep(0.3)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    try:
        follow(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "all")
    except KeyboardInterrupt:
        pass
