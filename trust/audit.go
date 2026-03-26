package trust

import (
	"io"
	"iter"
	"sync"
	"time"

	core "dappco.re/go/core"
	coreerr "dappco.re/go/core/log"
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
	result := core.JSONMarshal(d.String())
	if !result.OK {
		err, _ := result.Value.(error)
		return nil, err
	}
	return result.Value.([]byte), nil
}

// UnmarshalJSON implements custom JSON decoding for Decision.
func (d *Decision) UnmarshalJSON(data []byte) error {
	var s string
	result := core.JSONUnmarshal(data, &s)
	if !result.OK {
		err, _ := result.Value.(error)
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
		return coreerr.E("trust.Decision.UnmarshalJSON", "unknown decision: "+s, nil)
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
		dataResult := core.JSONMarshal(entry)
		if !dataResult.OK {
			err, _ := dataResult.Value.(error)
			return coreerr.E("trust.AuditLog.Record", "marshal failed", err)
		}
		data := append(dataResult.Value.([]byte), '\n')
		if _, err := l.writer.Write(data); err != nil {
			return coreerr.E("trust.AuditLog.Record", "write failed", err)
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
