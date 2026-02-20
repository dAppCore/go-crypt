package trust

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- AuditLog basic ---

func TestAuditRecord_Good(t *testing.T) {
	log := NewAuditLog(nil)

	result := EvalResult{
		Decision: Allow,
		Agent:    "Athena",
		Cap:      CapPushRepo,
		Reason:   "capability repo.push allowed for tier full",
	}
	err := log.Record(result, "host-uk/core")
	require.NoError(t, err)
	assert.Equal(t, 1, log.Len())
}

func TestAuditRecord_Good_EntryFields(t *testing.T) {
	log := NewAuditLog(nil)

	result := EvalResult{
		Decision: Deny,
		Agent:    "BugSETI-001",
		Cap:      CapPushRepo,
		Reason:   "denied",
	}
	err := log.Record(result, "host-uk/core")
	require.NoError(t, err)

	entries := log.Entries()
	require.Len(t, entries, 1)

	e := entries[0]
	assert.Equal(t, "BugSETI-001", e.Agent)
	assert.Equal(t, CapPushRepo, e.Cap)
	assert.Equal(t, "host-uk/core", e.Repo)
	assert.Equal(t, Deny, e.Decision)
	assert.Equal(t, "denied", e.Reason)
	assert.False(t, e.Timestamp.IsZero())
}

func TestAuditRecord_Good_NoRepo(t *testing.T) {
	log := NewAuditLog(nil)
	result := EvalResult{
		Decision: Allow,
		Agent:    "Athena",
		Cap:      CapCommentIssue,
		Reason:   "ok",
	}
	err := log.Record(result, "")
	require.NoError(t, err)

	entries := log.Entries()
	require.Len(t, entries, 1)
	assert.Empty(t, entries[0].Repo)
}

func TestAuditEntries_Good_Snapshot(t *testing.T) {
	log := NewAuditLog(nil)
	log.Record(EvalResult{Agent: "A", Cap: CapPushRepo, Decision: Allow, Reason: "ok"}, "")

	entries := log.Entries()
	require.Len(t, entries, 1)

	// Mutating the snapshot should not affect the log.
	entries[0].Agent = "MUTATED"
	assert.Equal(t, "A", log.Entries()[0].Agent)
}

func TestAuditEntries_Good_Empty(t *testing.T) {
	log := NewAuditLog(nil)
	assert.Empty(t, log.Entries())
}

func TestAuditEntries_Good_AppendOnly(t *testing.T) {
	log := NewAuditLog(nil)

	for i := 0; i < 5; i++ {
		log.Record(EvalResult{
			Agent:    fmt.Sprintf("agent-%d", i),
			Cap:      CapPushRepo,
			Decision: Allow,
			Reason:   "ok",
		}, "")
	}
	assert.Equal(t, 5, log.Len())
}

// --- EntriesFor ---

func TestAuditEntriesFor_Good(t *testing.T) {
	log := NewAuditLog(nil)

	log.Record(EvalResult{Agent: "Athena", Cap: CapPushRepo, Decision: Allow, Reason: "ok"}, "")
	log.Record(EvalResult{Agent: "Clotho", Cap: CapCreatePR, Decision: Allow, Reason: "ok"}, "")
	log.Record(EvalResult{Agent: "Athena", Cap: CapMergePR, Decision: Allow, Reason: "ok"}, "")

	athenaEntries := log.EntriesFor("Athena")
	assert.Len(t, athenaEntries, 2)
	for _, e := range athenaEntries {
		assert.Equal(t, "Athena", e.Agent)
	}
}

func TestAuditEntriesFor_Bad_NotFound(t *testing.T) {
	log := NewAuditLog(nil)
	log.Record(EvalResult{Agent: "Athena", Cap: CapPushRepo, Decision: Allow, Reason: "ok"}, "")

	assert.Empty(t, log.EntriesFor("NonExistent"))
}

// --- Writer output ---

func TestAuditRecord_Good_WritesToWriter(t *testing.T) {
	var buf bytes.Buffer
	log := NewAuditLog(&buf)

	result := EvalResult{
		Decision: Allow,
		Agent:    "Athena",
		Cap:      CapPushRepo,
		Reason:   "allowed",
	}
	err := log.Record(result, "host-uk/core")
	require.NoError(t, err)

	// Should have written a JSON line.
	output := buf.String()
	assert.True(t, strings.HasSuffix(output, "\n"))

	var entry AuditEntry
	err = json.Unmarshal([]byte(output), &entry)
	require.NoError(t, err)
	assert.Equal(t, "Athena", entry.Agent)
	assert.Equal(t, CapPushRepo, entry.Cap)
	assert.Equal(t, Allow, entry.Decision)
	assert.Equal(t, "host-uk/core", entry.Repo)
}

func TestAuditRecord_Good_MultipleLines(t *testing.T) {
	var buf bytes.Buffer
	log := NewAuditLog(&buf)

	for i := 0; i < 3; i++ {
		log.Record(EvalResult{
			Agent:    fmt.Sprintf("agent-%d", i),
			Cap:      CapPushRepo,
			Decision: Allow,
			Reason:   "ok",
		}, "")
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	assert.Len(t, lines, 3)

	// Each line should be valid JSON.
	for _, line := range lines {
		var entry AuditEntry
		err := json.Unmarshal([]byte(line), &entry)
		assert.NoError(t, err)
	}
}

func TestAuditRecord_Bad_WriterError(t *testing.T) {
	log := NewAuditLog(&failWriter{})

	result := EvalResult{
		Decision: Allow,
		Agent:    "Athena",
		Cap:      CapPushRepo,
		Reason:   "ok",
	}
	err := log.Record(result, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "write failed")

	// Entry should still be recorded in memory.
	assert.Equal(t, 1, log.Len())
}

// failWriter always returns an error.
type failWriter struct{}

func (f *failWriter) Write(_ []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

// --- Decision JSON marshalling ---

func TestDecisionJSON_Good_RoundTrip(t *testing.T) {
	decisions := []Decision{Deny, Allow, NeedsApproval}
	expected := []string{`"deny"`, `"allow"`, `"needs_approval"`}

	for i, d := range decisions {
		data, err := json.Marshal(d)
		require.NoError(t, err)
		assert.Equal(t, expected[i], string(data))

		var decoded Decision
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, d, decoded)
	}
}

func TestDecisionJSON_Bad_UnknownString(t *testing.T) {
	var d Decision
	err := json.Unmarshal([]byte(`"invalid"`), &d)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown decision")
}

func TestDecisionJSON_Bad_NonString(t *testing.T) {
	var d Decision
	err := json.Unmarshal([]byte(`42`), &d)
	assert.Error(t, err)
}

// --- Concurrent audit logging ---

func TestAuditConcurrent_Good(t *testing.T) {
	var buf bytes.Buffer
	log := NewAuditLog(&buf)

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)

	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			log.Record(EvalResult{
				Agent:    fmt.Sprintf("agent-%d", idx),
				Cap:      CapPushRepo,
				Decision: Allow,
				Reason:   "ok",
			}, "")
		}(i)
	}

	wg.Wait()
	assert.Equal(t, n, log.Len())
}

// --- Integration: PolicyEngine + AuditLog ---

func TestAuditPolicyIntegration_Good(t *testing.T) {
	var buf bytes.Buffer
	log := NewAuditLog(&buf)
	pe := newTestEngine(t)

	// Evaluate and record
	result := pe.Evaluate("Athena", CapPushRepo, "host-uk/core")
	err := log.Record(result, "host-uk/core")
	require.NoError(t, err)

	result = pe.Evaluate("BugSETI-001", CapPushRepo, "host-uk/core")
	err = log.Record(result, "host-uk/core")
	require.NoError(t, err)

	assert.Equal(t, 2, log.Len())

	// Verify entries match evaluation results.
	entries := log.Entries()
	assert.Equal(t, Allow, entries[0].Decision)
	assert.Equal(t, Deny, entries[1].Decision)
}
