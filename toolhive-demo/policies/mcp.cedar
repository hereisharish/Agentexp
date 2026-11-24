// ToolHive demo: Cedar policies evaluated by the external PDP.
//
// Request shape the PDP builds from each ToolHive question:
//   principal  User::"<keycloak sub>"   in Role::"<each realm role>"
//   action     Action::"call_tool"
//   resource   Tool::"<tool name>"      in MCPServer::"<thv workload name>"
//   context    { server, args?: { ...tool arguments... } }
//
// Cedar rules worth saying out loud on stage:
//   1. Default deny: nothing is allowed unless a permit matches.
//   2. Forbid wins: one matching forbid beats any number of permits.
//   3. A policy whose condition errors (e.g. args missing) is skipped.
//      ToolHive asks "could this user call X?" WITHOUT args when filtering
//      tools/list, so argument rules must be written as forbids guarded by
//      `context has args`, otherwise the tool would vanish from the list.
//
// Edit this file while the demo runs: the PDP reloads it within a second.

// ── Permits ─────────────────────────────────────────────────────────────

// Every signed-in user may read customer records.
@id("read-customers")
permit (
  principal,
  action == Action::"call_tool",
  resource
)
when { resource in [Tool::"list_customers", Tool::"get_customer"] };

// Support agents work tickets.
@id("support-update-tickets")
permit (
  principal in Role::"support",
  action == Action::"call_tool",
  resource == Tool::"update_ticket"
);

// Engineers may use every tool on the acme server...
@id("engineer-acme-all")
permit (
  principal in Role::"engineer",
  action == Action::"call_tool",
  resource in MCPServer::"acme"
);

// ...and may fetch web pages.
@id("engineer-fetch")
permit (
  principal in Role::"engineer",
  action == Action::"call_tool",
  resource == Tool::"fetch"
);

// ── Forbids (guardrails that no permit can override) ───────────────────

// Support's ceiling: whatever other roles a support identity picks up,
// it can only touch these three tools. (Try adding "engineer" to
// support-bot in Keycloak: it gains nothing.)
@id("support-ceiling")
forbid (
  principal in Role::"support",
  action == Action::"call_tool",
  resource
)
unless {
  resource in [Tool::"list_customers", Tool::"get_customer", Tool::"update_ticket"]
};

// Customer PII never leaves through export_report, whoever asks.
@id("no-pii-export")
forbid (
  principal,
  action == Action::"call_tool",
  resource == Tool::"export_report"
)
when { context has args && context.args has include_pii && context.args.include_pii == true };

// fetch may only reach approved hosts. Anything else (for example the local
// "attacker" listener) is denied with its arguments as evidence.
@id("fetch-allowlist")
forbid (
  principal,
  action == Action::"call_tool",
  resource == Tool::"fetch"
)
when {
  context has args && context.args has url &&
  !(context.args.url like "https://example.com*" ||
    context.args.url like "https://docs.stacklok.com/*")
};
