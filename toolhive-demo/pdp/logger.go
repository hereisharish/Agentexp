package main

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// DecisionLogger prints a one-line, human-readable decision to the console
// and a full JSON record to the decision log.
type DecisionLogger struct {
	mu    sync.Mutex
	out   io.Writer
	jsonl io.Writer
	color bool
}

func NewDecisionLogger(out, jsonl io.Writer, color bool) *DecisionLogger {
	return &DecisionLogger{out: out, jsonl: jsonl, color: color}
}

const (
	green = "\033[32m"
	red   = "\033[31m"
	dim   = "\033[2m"
	bold  = "\033[1m"
	reset = "\033[0m"
)

func (l *DecisionLogger) paint(code, s string) string {
	if !l.color {
		return s
	}
	return code + s + reset
}

func (l *DecisionLogger) Log(d Decision) {
	q := d.Query
	who := q.Username
	if who == "" {
		who = shortID(q.Subject)
	}
	roles := "-"
	if shown := visibleRoles(q.Roles); len(shown) > 0 {
		roles = strings.Join(shown, ",")
	}

	verdict := l.paint(bold+green, "ALLOW")
	if !d.Allow {
		verdict = l.paint(bold+red, "DENY ")
	}
	// A request without arguments is usually ToolHive filtering tools/list
	// (it asks "could this caller call X?" once per tool).
	phase := "call"
	if q.Args == nil {
		phase = "list?"
	}
	line := fmt.Sprintf("%s %s %-12s [%s] %s %s::%q %s %s",
		l.paint(dim, d.Time.Format("15:04:05")),
		verdict,
		who,
		roles,
		q.Action,
		q.Kind,
		q.Name,
		l.paint(dim, "@"+q.Server+" ("+phase+")"),
		l.paint(dim, "← "+d.Reason),
	)
	if len(q.Args) > 0 {
		line += l.paint(dim, " args="+compactArgs(q.Args))
	}
	for _, e := range d.Errors {
		line += "\n         " + l.paint(dim, "skipped (eval error) "+e)
	}

	rec := map[string]any{
		"time":       d.Time.UTC().Format(time.RFC3339Nano),
		"decision":   map[bool]string{true: "allow", false: "deny"}[d.Allow],
		"reason":     d.Reason,
		"determined": d.Determined,
		"errors":     d.Errors,
		"principal":  map[string]any{"sub": q.Subject, "username": q.Username, "roles": q.Roles},
		"action":     q.Action,
		"resource":   map[string]any{"type": q.Kind, "name": q.Name, "server": q.Server},
		"args":       q.Args,
		"probe":      d.Probe,
		"latency_us": d.Latency.Microseconds(),
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintln(l.out, line)
	b, _ := json.Marshal(rec)
	_, _ = l.jsonl.Write(append(b, '\n'))
}

func (l *DecisionLogger) Error(format string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "%s %s %s\n", time.Now().Format("15:04:05"), l.paint(bold+red, "ERROR"), fmt.Sprintf(format, a...))
}

func compactArgs(args map[string]any) string {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v, _ := json.Marshal(args[k])
		s := string(v)
		if len(s) > 60 {
			s = s[:57] + "..."
		}
		parts = append(parts, k+"="+s)
	}
	return "{" + strings.Join(parts, " ") + "}"
}

// visibleRoles hides Keycloak's built-in roles so the log shows the roles
// the policies are about. They are still passed to Cedar.
func visibleRoles(roles []string) []string {
	out := make([]string, 0, len(roles))
	for _, r := range roles {
		if strings.HasPrefix(r, "default-roles-") || r == "offline_access" || r == "uma_authorization" {
			continue
		}
		out = append(out, r)
	}
	return out
}

func shortID(s string) string {
	if len(s) > 12 {
		return s[:8] + "…"
	}
	return s
}
