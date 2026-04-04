package trust

import (
	"io"
	"sync"
	"testing"

	core "dappco.re/go/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- AuditLog basic ---

func TestAudit_AuditRecord_Good(t *testing.T) {
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

func TestAudit_AuditRecord_Good_EntryFields(t *testing.T) {
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

func TestAudit_AuditRecord_Good_NoRepo(t *testing.T) {
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

func TestAudit_AuditEntries_Good_Snapshot(t *testing.T) {
	log := NewAuditLog(nil)
	log.Record(EvalResult{Agent: "A", Cap: CapPushRepo, Decision: Allow, Reason: "ok"}, "")

	entries := log.Entries()
	require.Len(t, entries, 1)

	// Mutating the snapshot should not affect the log.
	entries[0].Agent = "MUTATED"
	assert.Equal(t, "A", log.Entries()[0].Agent)
}

func TestAudit_AuditEntries_Good_Empty(t *testing.T) {
	log := NewAuditLog(nil)
	assert.Empty(t, log.Entries())
}

func TestAudit_AuditEntries_Good_AppendOnly(t *testing.T) {
	log := NewAuditLog(nil)

	for i := range 5 {
		log.Record(EvalResult{
			Agent:    core.Sprintf("agent-%d", i),
			Cap:      CapPushRepo,
			Decision: Allow,
			Reason:   "ok",
		}, "")
	}
	assert.Equal(t, 5, log.Len())
}

// --- EntriesFor ---

func TestAudit_AuditEntriesFor_Good(t *testing.T) {
	log := NewAuditLog(nil)

	log.Record(EvalResult{Agent: "Athena", Cap: CapPushRepo, Decision: Allow, Reason: "ok"}, "")
	log.Record(EvalResult{Agent: "Clotho", Cap: CapCreatePR, Decision: Allow, Reason: "ok"}, "")
	log.Record(EvalResult{Agent: "Athena", Cap: CapMergePR, Decision: Allow, Reason: "ok"}, "")

	athenaEntries := log.EntriesFor("Athena")
	assert.Len(t, athenaEntries, 2)
	for _, e := range athenaEntries {
		assert.Equal(t, "Athena", e.Agent)
	}

	// Test iterator version
	count := 0
	for e := range log.EntriesForSeq("Athena") {
		assert.Equal(t, "Athena", e.Agent)
		count++
	}
	assert.Equal(t, 2, count)
}

func TestAudit_AuditEntriesSeq_Good(t *testing.T) {
	log := NewAuditLog(nil)
	log.Record(EvalResult{Agent: "Athena", Cap: CapPushRepo, Decision: Allow, Reason: "ok"}, "")
	log.Record(EvalResult{Agent: "Clotho", Cap: CapCreatePR, Decision: Allow, Reason: "ok"}, "")

	count := 0
	for range log.EntriesSeq() {
		count++
	}
	assert.Equal(t, 2, count)
}

func TestAudit_AuditEntriesFor_Bad_NotFound(t *testing.T) {
	log := NewAuditLog(nil)
	log.Record(EvalResult{Agent: "Athena", Cap: CapPushRepo, Decision: Allow, Reason: "ok"}, "")

	assert.Empty(t, log.EntriesFor("NonExistent"))
}

// --- Writer output ---

func TestAudit_AuditRecord_Good_WritesToWriter(t *testing.T) {
	buf := core.NewBuilder()
	log := NewAuditLog(buf)

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
	assert.True(t, core.HasSuffix(output, "\n"))

	var entry AuditEntry
	decodeResult := core.JSONUnmarshal([]byte(output), &entry)
	require.Truef(t, decodeResult.OK, "failed to unmarshal audit entry: %v", decodeResult.Value)
	assert.Equal(t, "Athena", entry.Agent)
	assert.Equal(t, CapPushRepo, entry.Cap)
	assert.Equal(t, Allow, entry.Decision)
	assert.Equal(t, "host-uk/core", entry.Repo)
}

func TestAudit_AuditRecord_Good_MultipleLines(t *testing.T) {
	buf := core.NewBuilder()
	log := NewAuditLog(buf)

	for i := range 3 {
		log.Record(EvalResult{
			Agent:    core.Sprintf("agent-%d", i),
			Cap:      CapPushRepo,
			Decision: Allow,
			Reason:   "ok",
		}, "")
	}

	lines := core.Split(core.Trim(buf.String()), "\n")
	assert.Len(t, lines, 3)

	// Each line should be valid JSON.
	for _, line := range lines {
		var entry AuditEntry
		result := core.JSONUnmarshal([]byte(line), &entry)
		assert.Truef(t, result.OK, "failed to unmarshal audit line: %v", result.Value)
	}
}

func TestAudit_AuditRecord_Bad_WriterError(t *testing.T) {
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

func TestAudit_DecisionJSON_Good_RoundTrip(t *testing.T) {
	decisions := []Decision{Deny, Allow, NeedsApproval}
	expected := []string{`"deny"`, `"allow"`, `"needs_approval"`}

	for i, d := range decisions {
		result := core.JSONMarshal(d)
		require.Truef(t, result.OK, "failed to marshal decision: %v", result.Value)
		assert.Equal(t, expected[i], string(result.Value.([]byte)))

		var decoded Decision
		decodeResult := core.JSONUnmarshal(result.Value.([]byte), &decoded)
		require.Truef(t, decodeResult.OK, "failed to unmarshal decision: %v", decodeResult.Value)
		assert.Equal(t, d, decoded)
	}
}

func TestAudit_DecisionJSON_Bad_UnknownString(t *testing.T) {
	var d Decision
	result := core.JSONUnmarshal([]byte(`"invalid"`), &d)
	err, _ := result.Value.(error)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown decision")
}

func TestAudit_DecisionJSON_Bad_NonString(t *testing.T) {
	var d Decision
	result := core.JSONUnmarshal([]byte(`42`), &d)
	err, _ := result.Value.(error)
	assert.Error(t, err)
}

// --- Concurrent audit logging ---

func TestAudit_AuditConcurrent_Good(t *testing.T) {
	buf := core.NewBuilder()
	log := NewAuditLog(buf)

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)

	for i := range n {
		go func(idx int) {
			defer wg.Done()
			log.Record(EvalResult{
				Agent:    core.Sprintf("agent-%d", idx),
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

func TestAudit_AuditPolicyIntegration_Good(t *testing.T) {
	buf := core.NewBuilder()
	log := NewAuditLog(buf)
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
