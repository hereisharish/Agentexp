// Command pdp is the demo's external Policy Decision Point (PDP).
//
// ToolHive (the Policy Enforcement Point) is started with an "httpv1"
// authorization config. For every MCP request it POSTs a PORC document
// (Principal, Operation, Resource, Context) to /decision on this service and
// enforces the {"allow": bool} answer. This service never sees MCP traffic;
// it only answers authorization questions.
//
// Policies are plain Cedar files read from a directory and reloaded whenever
// they change, so a policy edit takes effect on the next request without
// restarting ToolHive or the MCP client.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", envOr("PDP_ADDR", ":9000"), "listen address")
	policyDir := flag.String("policies", envOr("PDP_POLICY_DIR", "/policies"), "directory of *.cedar files")
	decisionLog := flag.String("decision-log", envOr("PDP_DECISION_LOG", ""), "optional JSONL file for decisions")
	names := flag.String("names", envOr("PDP_DISPLAY_NAMES", ""), "optional JSON file mapping sub -> display name")
	color := flag.Bool("color", os.Getenv("NO_COLOR") == "", "colour console output")
	flag.Parse()

	if *names != "" {
		b, err := os.ReadFile(*names)
		if err != nil {
			log.Fatalf("read display names: %v", err)
		}
		if err := json.Unmarshal(b, &displayNames); err != nil {
			log.Fatalf("parse display names: %v", err)
		}
	}

	store := NewPolicyStore(*policyDir)
	if err := store.Reload(); err != nil {
		log.Fatalf("initial policy load failed: %v", err)
	}
	go store.Watch(time.Second)

	var sink io.Writer = io.Discard
	if *decisionLog != "" {
		f, err := os.OpenFile(*decisionLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			log.Fatalf("open decision log: %v", err)
		}
		defer f.Close()
		sink = f
	}
	logger := NewDecisionLogger(os.Stdout, sink, *color)

	mux := http.NewServeMux()
	mux.HandleFunc("POST /decision", decisionHandler(store, logger))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /policies", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(store.Summary())
	})

	log.Printf("Cedar PDP listening on %s (policies: %s)", *addr, *policyDir)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func decisionHandler(store *PolicyStore, logger *DecisionLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		var porc PORC
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&porc); err != nil {
			// Malformed question: answer "deny" rather than an error, so a
			// misbehaving caller can never be read as permission.
			writeDecision(w, false)
			logger.Error("bad PORC: %v", err)
			return
		}

		d := store.Decide(porc)
		d.Probe = r.URL.Query().Get("probe") == "true"
		d.Latency = time.Since(start)
		logger.Log(d)
		writeDecision(w, d.Allow)
	}
}

func writeDecision(w http.ResponseWriter, allow bool) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"allow": allow})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
