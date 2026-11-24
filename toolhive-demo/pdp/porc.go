package main

import (
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go"
)

// PORC is the authorization question ToolHive sends (see ToolHive's
// pkg/authz/authorizers/http/porc.go). Example:
//
//	{
//	  "principal": {"sub": "8f1c…", "roles": ["support"]},
//	  "operation": "mcp:tool:call",
//	  "resource":  "mrn:mcp:acme:tool:get_customer",
//	  "context":   {"mcp": {"feature": "tool", "operation": "call",
//	                        "resource_id": "get_customer", "args": {"id": "42"}}}
//	}
type PORC struct {
	Principal map[string]any `json:"principal"`
	Operation string         `json:"operation"`
	Resource  string         `json:"resource"`
	Context   map[string]any `json:"context"`
}

// displayNames maps token subjects (Keycloak user IDs) to readable names for
// the decision log. ToolHive's "standard" claim mapping forwards only sub,
// roles, groups and scopes, so the username never reaches the PDP.
var displayNames = map[string]string{}

// cedarQuery is the PORC translated into Cedar terms.
type cedarQuery struct {
	Request  cedar.Request
	Entities cedar.EntityMap

	// Human-readable fields for the decision log.
	Subject  string
	Username string
	Roles    []string
	Action   string
	Server   string
	Kind     string
	Name     string
	Args     map[string]any
}

// actionFor maps ToolHive operations ("mcp:<feature>:<operation>") to the
// same action names ToolHive's built-in Cedar authorizer uses, so policies
// are portable between the external PDP and the embedded cedarv1 mode.
func actionFor(operation string) string {
	switch operation {
	case "mcp:tool:call":
		return "call_tool"
	case "mcp:prompt:get":
		return "get_prompt"
	case "mcp:resource:read":
		return "read_resource"
	case "mcp:skill:get":
		return "get_skill"
	}
	return strings.ReplaceAll(strings.TrimPrefix(operation, "mcp:"), ":", "_")
}

// entityTypeFor maps an MCP feature to a Cedar entity type, again matching
// ToolHive's built-in Cedar authorizer.
func entityTypeFor(feature string) string {
	switch feature {
	case "tool":
		return "Tool"
	case "prompt":
		return "Prompt"
	case "resource":
		return "Resource"
	case "skill":
		return "Skill"
	}
	if feature == "" {
		return "Unknown"
	}
	return strings.ToUpper(feature[:1]) + feature[1:]
}

// parseMRN splits "mrn:mcp:<server>:<feature>:<id>". The id may itself
// contain colons (resource URIs), so only the first four separators count.
func parseMRN(mrn string) (server, feature, id string, err error) {
	parts := strings.SplitN(mrn, ":", 5)
	if len(parts) != 5 || parts[0] != "mrn" || parts[1] != "mcp" {
		return "", "", "", fmt.Errorf("unexpected resource %q", mrn)
	}
	return parts[2], parts[3], parts[4], nil
}

// toQuery builds the Cedar request and the entity store for one PORC.
//
//	principal: User::"<sub>"   attrs {sub, username, roles}   parents Role::"<r>" for each role
//	action:    Action::"call_tool" | "get_prompt" | "read_resource" | …
//	resource:  Tool::"<name>"  attrs {name, server}           parent  MCPServer::"<server>"
//	context:   {server, args, annotations}
func toQuery(p PORC) (cedarQuery, error) {
	server, feature, name, err := parseMRN(p.Resource)
	if err != nil {
		return cedarQuery{}, err
	}

	q := cedarQuery{
		Action: actionFor(p.Operation),
		Server: server,
		Kind:   entityTypeFor(feature),
		Name:   name,
	}
	q.Subject, _ = p.Principal["sub"].(string)
	if q.Subject == "" {
		q.Subject = "anonymous"
	}
	q.Username, _ = p.Principal["preferred_username"].(string)
	if q.Username == "" {
		q.Username = displayNames[q.Subject]
	}
	q.Roles = stringList(p.Principal["roles"])
	sort.Strings(q.Roles)

	entities := cedar.EntityMap{}

	// Principal and its roles.
	userUID := cedar.NewEntityUID("User", cedar.String(q.Subject))
	roleVals := make([]cedar.Value, 0, len(q.Roles))
	parents := make([]cedar.EntityUID, 0, len(q.Roles))
	for _, r := range q.Roles {
		roleVals = append(roleVals, cedar.String(r))
		ruid := cedar.NewEntityUID("Role", cedar.String(r))
		parents = append(parents, ruid)
		entities[ruid] = cedar.Entity{UID: ruid}
	}
	userAttrs := cedar.RecordMap{
		"sub":   cedar.String(q.Subject),
		"roles": cedar.NewSet(roleVals...),
	}
	for k, v := range p.Principal {
		if _, taken := userAttrs[cedar.String(k)]; !taken {
			userAttrs[cedar.String(k)] = toValue(v)
		}
	}
	entities[userUID] = cedar.Entity{
		UID:        userUID,
		Parents:    cedar.NewEntityUIDSet(parents...),
		Attributes: cedar.NewRecord(userAttrs),
	}

	// Resource and the MCP server it belongs to.
	serverUID := cedar.NewEntityUID("MCPServer", cedar.String(server))
	entities[serverUID] = cedar.Entity{UID: serverUID}
	resUID := cedar.NewEntityUID(cedar.EntityType(q.Kind), cedar.String(name))
	entities[resUID] = cedar.Entity{
		UID:     resUID,
		Parents: cedar.NewEntityUIDSet(serverUID),
		Attributes: cedar.NewRecord(cedar.RecordMap{
			"name":   cedar.String(name),
			"server": cedar.String(server),
		}),
	}

	// Context: flatten ToolHive's context.mcp.{args,annotations} to the top
	// level so policies read naturally (context.args.url).
	ctx := cedar.RecordMap{"server": cedar.String(server)}
	if mcp, ok := p.Context["mcp"].(map[string]any); ok {
		if args, ok := mcp["args"].(map[string]any); ok && len(args) > 0 {
			q.Args = args
			ctx["args"] = toValue(args)
		}
		if ann, ok := mcp["annotations"].(map[string]any); ok && len(ann) > 0 {
			ctx["annotations"] = toValue(ann)
		}
	}

	q.Entities = entities
	q.Request = cedar.Request{
		Principal: userUID,
		Action:    cedar.NewEntityUID("Action", cedar.String(q.Action)),
		Resource:  resUID,
		Context:   cedar.NewRecord(ctx),
	}
	return q, nil
}

// toValue converts decoded JSON into a Cedar value. Cedar has no floating
// point type, so non-integral numbers become strings.
func toValue(v any) cedar.Value {
	switch t := v.(type) {
	case string:
		return cedar.String(t)
	case bool:
		return cedar.Boolean(t)
	case float64:
		if t == math.Trunc(t) && math.Abs(t) < 1<<53 {
			return cedar.Long(int64(t))
		}
		return cedar.String(fmt.Sprint(t))
	case []any:
		vals := make([]cedar.Value, 0, len(t))
		for _, e := range t {
			vals = append(vals, toValue(e))
		}
		return cedar.NewSet(vals...)
	case map[string]any:
		rec := cedar.RecordMap{}
		for k, e := range t {
			rec[cedar.String(k)] = toValue(e)
		}
		return cedar.NewRecord(rec)
	case nil:
		return cedar.String("")
	}
	return cedar.String(fmt.Sprint(v))
}

func stringList(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	case string:
		if t == "" {
			return nil
		}
		return strings.Fields(strings.ReplaceAll(t, ",", " "))
	}
	return nil
}
