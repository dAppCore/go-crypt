package trust

import (
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"sync"
	"time"
)

// AuditEntry records a single policy evaluation for compliance.
type AuditEntry struct {
	// Timestamp is when the evaluation occurred.
	Timestamp time.Time `json:"timestamp"`
	// Agent is the name of the agent being evaluated.
	Agent string `json:"agent"`
	// Cap is the capability that was evaluated.
	Cap Capability `json:"capability"`
	// Repo is the repo context (empty if not repo-scoped).
	Repo string `json:"repo,omitempty"`
	// Decision is the evaluation outcome.
	Decision Decision `json:"decision"`
	// Reason is the human-readable reason for the decision.
	Reason string `json:"reason"`
}

// MarshalJSON implements custom JSON encoding for Decision.
func (d Decision) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.String())
}

// UnmarshalJSON implements custom JSON decoding for Decision.
func (d *Decision) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	switch s {
	case "deny":
		*d = Deny
	case "allow":
		*d = Allow
	case "needs_approval":
		*d = NeedsApproval
	default:
		return fmt.Errorf("trust: unknown decision %q", s)
	}
	return nil
}

// AuditLog is an append-only log of policy evaluations.
type AuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
	writer  io.Writer
}

// NewAuditLog creates an in-memory audit log. If a writer is provided,
// each entry is also written as a JSON line to that writer (append-only).
func NewAuditLog(w io.Writer) *AuditLog {
	return &AuditLog{
		writer: w,
	}
}

// Record appends an evaluation result to the audit log.
func (l *AuditLog) Record(result EvalResult, repo string) error {
	entry := AuditEntry{
		Timestamp: time.Now(),
		Agent:     result.Agent,
		Cap:       result.Cap,
		Repo:      repo,
		Decision:  result.Decision,
		Reason:    result.Reason,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = append(l.entries, entry)

	if l.writer != nil {
		data, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("trust.AuditLog.Record: marshal failed: %w", err)
		}
		data = append(data, '\n')
		if _, err := l.writer.Write(data); err != nil {
			return fmt.Errorf("trust.AuditLog.Record: write failed: %w", err)
		}
	}

	return nil
}

// Entries returns a snapshot of all audit entries.
func (l *AuditLog) Entries() []AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make([]AuditEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

// EntriesSeq returns an iterator over all audit entries.
func (l *AuditLog) EntriesSeq() iter.Seq[AuditEntry] {
	return func(yield func(AuditEntry) bool) {
		l.mu.Lock()
		defer l.mu.Unlock()

		for _, e := range l.entries {
			if !yield(e) {
				return
			}
		}
	}
}

// Len returns the number of entries in the log.
func (l *AuditLog) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// EntriesFor returns all audit entries for a specific agent.
func (l *AuditLog) EntriesFor(agent string) []AuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	var out []AuditEntry
	for _, e := range l.entries {
		if e.Agent == agent {
			out = append(out, e)
		}
	}
	return out
}

// EntriesForSeq returns an iterator over audit entries for a specific agent.
func (l *AuditLog) EntriesForSeq(agent string) iter.Seq[AuditEntry] {
	return func(yield func(AuditEntry) bool) {
		l.mu.Lock()
		defer l.mu.Unlock()

		for _, e := range l.entries {
			if e.Agent == agent {
				if !yield(e) {
					return
				}
			}
		}
	}
}
