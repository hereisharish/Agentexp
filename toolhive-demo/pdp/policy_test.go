package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	alice      = "11111111-1111-4111-8111-111111111111" // engineer
	supportBot = "22222222-2222-4222-8222-222222222222" // support
	bob        = "33333333-3333-4333-8333-333333333333" // no roles
)

func porc(sub string, roles []string, server, tool string, args map[string]any) PORC {
	p := PORC{
		Principal: map[string]any{"sub": sub},
		Operation: "mcp:tool:call",
		Resource:  "mrn:mcp:" + server + ":tool:" + tool,
		Context:   map[string]any{},
	}
	if roles != nil {
		rs := make([]any, len(roles))
		for i, r := range roles {
			rs[i] = r
		}
		p.Principal["roles"] = rs
	}
	if args != nil {
		p.Context["mcp"] = map[string]any{"feature": "tool", "operation": "call", "resource_id": tool, "args": args}
	}
	return p
}

func demoStore(t *testing.T) *PolicyStore {
	t.Helper()
	s := NewPolicyStore(filepath.Join("..", "policies"))
	if err := s.Reload(); err != nil {
		t.Fatalf("load demo policies: %v", err)
	}
	return s
}

func TestDemoPolicies(t *testing.T) {
	s := demoStore(t)
	eng := []string{"engineer"}
	sup := []string{"support"}

	cases := []struct {
		name   string
		p      PORC
		allow  bool
		reason string
	}{
		// tools/list filtering (no args)
		{"bob lists get_customer", porc(bob, nil, "acme", "get_customer", nil), true, "read-customers"},
		{"bob cannot see update_ticket", porc(bob, nil, "acme", "update_ticket", nil), false, "default deny"},
		{"support sees update_ticket", porc(supportBot, sup, "acme", "update_ticket", nil), true, "support-update-tickets"},
		{"support cannot see export_report", porc(supportBot, sup, "acme", "export_report", nil), false, "support-ceiling"},
		{"support cannot see fetch", porc(supportBot, sup, "fetch", "fetch", nil), false, "support-ceiling"},
		{"engineer sees export_report", porc(alice, eng, "acme", "export_report", nil), true, "engineer-acme-all"},
		{"engineer sees fetch (no args yet)", porc(alice, eng, "fetch", "fetch", nil), true, "engineer-fetch"},
		{"engineer sees delete_customer", porc(alice, eng, "acme", "delete_customer", nil), true, "engineer-acme-all"},

		// calls with arguments
		{"support reads customer", porc(supportBot, sup, "acme", "get_customer", map[string]any{"customer_id": "42"}), true, "read-customers"},
		{"engineer export without PII", porc(alice, eng, "acme", "export_report", map[string]any{"include_pii": false, "destination": "s3://x"}), true, "engineer-acme-all"},
		{"engineer export with PII", porc(alice, eng, "acme", "export_report", map[string]any{"include_pii": true, "destination": "s3://x"}), false, "no-pii-export"},
		{"engineer fetch allowlisted", porc(alice, eng, "fetch", "fetch", map[string]any{"url": "https://example.com/"}), true, "engineer-fetch"},
		{"engineer fetch attacker", porc(alice, eng, "fetch", "fetch", map[string]any{"url": "http://host.docker.internal:9999/collect?d=secret"}), false, "fetch-allowlist"},
		{"engineer fetch lookalike host", porc(alice, eng, "fetch", "fetch", map[string]any{"url": "https://example.com.evil.io/"}), true, "engineer-fetch"},

		// forbid wins over permit: support-bot that also gets engineer
		{"support+engineer still capped", porc(supportBot, []string{"engineer", "support"}, "acme", "delete_customer", map[string]any{"customer_id": "42"}), false, "support-ceiling"},
		{"support+engineer cannot fetch", porc(supportBot, []string{"engineer", "support"}, "fetch", "fetch", nil), false, "support-ceiling"},

		// malformed resource
		{"bad resource", PORC{Principal: map[string]any{"sub": bob}, Operation: "mcp:tool:call", Resource: "nope"}, false, "unexpected resource"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := s.Decide(c.p)
			if d.Allow != c.allow {
				t.Fatalf("allow=%v want %v (%s)", d.Allow, c.allow, d.Reason)
			}
			if !strings.Contains(d.Reason, c.reason) {
				t.Fatalf("reason %q does not mention %q", d.Reason, c.reason)
			}
		})
	}
}

// The lookalike case above documents a real weakness of `like "https://example.com*"`.
// It is kept deliberately as a talking point; the network allowlist (layer 2)
// is what stops it. This test pins that the stricter pattern closes it.
func TestStricterPatternClosesLookalike(t *testing.T) {
	dir := t.TempDir()
	src := `
permit(principal, action, resource);
@id("fetch-allowlist-strict")
forbid(principal, action == Action::"call_tool", resource == Tool::"fetch")
when { context has args && context.args has url && !(context.args.url like "https://example.com/*") };`
	if err := os.WriteFile(filepath.Join(dir, "p.cedar"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewPolicyStore(dir)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	d := s.Decide(porc(alice, nil, "fetch", "fetch", map[string]any{"url": "https://example.com.evil.io/"}))
	if d.Allow {
		t.Fatal("strict pattern should deny lookalike host")
	}
}

func TestBrokenPolicyKeepsPreviousSet(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "p.cedar")
	if err := os.WriteFile(f, []byte(`@id("all") permit(principal, action, resource);`), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewPolicyStore(dir)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte(`permit(principal, action, resource`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil {
		t.Fatal("expected parse error")
	}
	if !s.Decide(porc(bob, nil, "acme", "anything", nil)).Allow {
		t.Fatal("previous policies should still be in force")
	}
}

func TestWatchPicksUpEdits(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "p.cedar")
	if err := os.WriteFile(f, []byte(`@id("all") permit(principal, action, resource);`), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewPolicyStore(dir)
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	go s.Watch(20 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)
	if err := os.WriteFile(f, []byte(`@id("none") forbid(principal, action, resource);`), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !s.Decide(porc(bob, nil, "acme", "x", nil)).Allow {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("edit was not picked up")
}

func TestDecisionEndpoint(t *testing.T) {
	s := demoStore(t)
	var console, jsonl bytes.Buffer
	h := decisionHandler(s, NewDecisionLogger(&console, &jsonl, false))

	body, _ := json.Marshal(porc(supportBot, []string{"support"}, "acme", "export_report", map[string]any{"include_pii": true}))
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/decision", bytes.NewReader(body)))

	var got map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["allow"] {
		t.Fatal("support must not export")
	}
	if !strings.Contains(console.String(), "DENY") || !strings.Contains(jsonl.String(), `"decision":"deny"`) {
		t.Fatalf("decision not logged:\n%s\n%s", console.String(), jsonl.String())
	}

	// Garbage in -> deny out.
	rec = httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodPost, "/decision", strings.NewReader("{")))
	if strings.Contains(rec.Body.String(), "true") {
		t.Fatal("malformed request must be denied")
	}
}
