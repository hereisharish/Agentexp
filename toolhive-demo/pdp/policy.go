package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cedar-policy/cedar-go"
)

// PolicyStore holds the current Cedar policy set and reloads it from disk.
type PolicyStore struct {
	dir string

	mu       sync.RWMutex
	set      *cedar.PolicySet
	names    map[cedar.PolicyID]string // policy ID -> @id annotation (or file:index)
	effects  map[cedar.PolicyID]string // policy ID -> "permit" | "forbid"
	files    []string
	loadedAt time.Time
	lastSig  string
	lastErr  string
}

func NewPolicyStore(dir string) *PolicyStore {
	return &PolicyStore{dir: dir}
}

// Reload parses every *.cedar file in the directory. If any file fails to
// parse, the previously loaded policies stay in force: a typo in a policy
// edit must never open the gates.
func (s *PolicyStore) Reload() error {
	files, err := filepath.Glob(filepath.Join(s.dir, "*.cedar"))
	if err != nil {
		return err
	}
	sort.Strings(files)

	set := cedar.NewPolicySet()
	names := map[cedar.PolicyID]string{}
	effects := map[cedar.PolicyID]string{}
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		fileSet, err := cedar.NewPolicySetFromBytes(filepath.Base(f), src)
		if err != nil {
			s.mu.Lock()
			s.lastErr = err.Error()
			s.mu.Unlock()
			return fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		base := strings.TrimSuffix(filepath.Base(f), ".cedar")
		for id, p := range fileSet.All() {
			newID := cedar.PolicyID(base + "/" + string(id))
			name := string(id)
			if v, ok := p.Annotations()["id"]; ok && v != "" {
				name = string(v)
				newID = cedar.PolicyID(base + "/" + name)
			}
			if !set.Add(newID, p) {
				return fmt.Errorf("%s: duplicate policy id %q", filepath.Base(f), name)
			}
			names[newID] = name
			effects[newID] = effectOf(p)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.set, s.names, s.effects = set, names, effects
	s.files = files
	s.loadedAt = time.Now()
	s.lastErr = ""
	s.lastSig = signature(files)
	return nil
}

// Watch polls the policy directory and reloads on any change. Polling (not
// inotify) keeps it working on Docker Desktop bind mounts.
func (s *PolicyStore) Watch(every time.Duration) {
	for range time.Tick(every) {
		files, _ := filepath.Glob(filepath.Join(s.dir, "*.cedar"))
		sort.Strings(files)
		sig := signature(files)
		s.mu.RLock()
		same := sig == s.lastSig
		s.mu.RUnlock()
		if same {
			continue
		}
		if err := s.Reload(); err != nil {
			log.Printf("⚠️  policy reload FAILED, keeping previous policies: %v", err)
			s.mu.Lock()
			s.lastSig = sig // do not retry until the file changes again
			s.mu.Unlock()
			continue
		}
		log.Printf("🔄 policies reloaded: %d policies from %d file(s)", s.count(), len(files))
	}
}

func (s *PolicyStore) count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.names)
}

// Decision is one answered authorization question, with the evidence.
type Decision struct {
	Time       time.Time
	Allow      bool
	Probe      bool
	Latency    time.Duration
	Query      cedarQuery
	Determined []string // policies that determined the outcome
	Errors     []string // policies that failed to evaluate (treated as not matching)
	Reason     string
}

// Decide evaluates a PORC against the current policies.
func (s *PolicyStore) Decide(p PORC) Decision {
	d := Decision{Time: time.Now()}
	q, err := toQuery(p)
	if err != nil {
		d.Reason = "deny: " + err.Error()
		return d
	}
	d.Query = q

	s.mu.RLock()
	set, names := s.set, s.names
	s.mu.RUnlock()

	decision, diag := set.IsAuthorized(q.Entities, q.Request)
	d.Allow = decision == cedar.Allow
	for _, r := range diag.Reasons {
		d.Determined = append(d.Determined, names[r.PolicyID])
	}
	for _, e := range diag.Errors {
		d.Errors = append(d.Errors, fmt.Sprintf("%s: %s", names[e.PolicyID], e.Message))
	}
	switch {
	case d.Allow:
		d.Reason = "permitted by " + strings.Join(d.Determined, ", ")
	case len(d.Determined) > 0:
		d.Reason = "forbidden by " + strings.Join(d.Determined, ", ")
	default:
		d.Reason = "no permit matched (default deny)"
	}
	return d
}

// Summary describes the loaded policies for GET /policies.
func (s *PolicyStore) Summary() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.names))
	for id, name := range s.names {
		ids = append(ids, fmt.Sprintf("%s %s", s.effects[id], name))
	}
	sort.Strings(ids)
	return map[string]any{
		"files":      s.files,
		"policies":   ids,
		"loaded_at":  s.loadedAt.Format(time.RFC3339),
		"last_error": s.lastErr,
	}
}

func effectOf(p *cedar.Policy) string {
	text := strings.TrimSpace(string(p.MarshalCedar()))
	// Skip leading annotations to find the effect keyword.
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "forbid") {
			return "forbid"
		}
		if strings.HasPrefix(line, "permit") {
			return "permit"
		}
	}
	return "?"
}

func signature(files []string) string {
	var b strings.Builder
	for _, f := range files {
		if st, err := os.Stat(f); err == nil {
			fmt.Fprintf(&b, "%s:%d:%d;", f, st.Size(), st.ModTime().UnixNano())
		}
	}
	return b.String()
}
