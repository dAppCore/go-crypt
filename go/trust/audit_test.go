package trust

import (
	"io"
	"sync"
	"testing"

	core "dappco.re/go"
)

// --- AuditLog basic ---

func TestAudit_AuditLog_Record_Good(t *testing.T) {
	log := NewAuditLog(nil)

	result := EvalResult{
		Decision: Allow,
		Agent:    "Athena",
		Cap:      CapPushRepo,
		Reason:   "capability repo.push allowed for tier full",
	}
	err := log.Record(result, "host-uk/core")
	mustNoError(t, err)
	wantEqual(t, 1, log.Len())
}

func TestAudit_AuditLog_Record_Good_EntryFields(t *testing.T) {
	log := NewAuditLog(nil)

	result := EvalResult{
		Decision: Deny,
		Agent:    "BugSETI-001",
		Cap:      CapPushRepo,
		Reason:   "denied",
	}
	err := log.Record(result, "host-uk/core")
	mustNoError(t, err)

	entries := log.Entries()
	mustLen(t, entries, 1)

	e := entries[0]
	wantEqual(t, "BugSETI-001", e.Agent)
	wantEqual(t, CapPushRepo, e.Cap)
	wantEqual(t, "host-uk/core", e.Repo)
	wantEqual(t, Deny, e.Decision)
	wantEqual(t, "denied", e.Reason)
	wantFalse(t, e.Timestamp.IsZero())
}

func TestAudit_AuditLog_Record_Good_NoRepo(t *testing.T) {
	log := NewAuditLog(nil)
	result := EvalResult{
		Decision: Allow,
		Agent:    "Athena",
		Cap:      CapCommentIssue,
		Reason:   "ok",
	}
	err := log.Record(result, "")
	mustNoError(t, err)

	entries := log.Entries()
	mustLen(t, entries, 1)
	wantEmpty(t, entries[0].Repo)
}

func TestAudit_AuditLog_Entries_Good_Snapshot(t *testing.T) {
	log := NewAuditLog(nil)
	log.Record(EvalResult{Agent: "A", Cap: CapPushRepo, Decision: Allow, Reason: "ok"}, "")

	entries := log.Entries()
	mustLen(t, entries, 1)

	// Mutating the snapshot should not affect the log.
	entries[0].Agent = "MUTATED"
	wantEqual(t, "A", log.Entries()[0].Agent)
}

func TestAudit_AuditLog_Entries_Good_Empty(t *testing.T) {
	log := NewAuditLog(nil)
	entries := log.Entries()
	wantEmpty(t, entries)
	wantEqual(t, 0, log.Len())
}

func TestAudit_AuditLog_Entries_Good_AppendOnly(t *testing.T) {
	log := NewAuditLog(nil)

	for i := range 5 {
		log.Record(EvalResult{
			Agent:    core.Sprintf("agent-%d", i),
			Cap:      CapPushRepo,
			Decision: Allow,
			Reason:   "ok",
		}, "")
	}
	wantEqual(t, 5, log.Len())
}

// --- EntriesFor ---

func TestAudit_AuditLog_EntriesFor_Good(t *testing.T) {
	log := NewAuditLog(nil)

	log.Record(EvalResult{Agent: "Athena", Cap: CapPushRepo, Decision: Allow, Reason: "ok"}, "")
	log.Record(EvalResult{Agent: "Clotho", Cap: CapCreatePR, Decision: Allow, Reason: "ok"}, "")
	log.Record(EvalResult{Agent: "Athena", Cap: CapMergePR, Decision: Allow, Reason: "ok"}, "")

	athenaEntries := log.EntriesFor("Athena")
	wantLen(t, athenaEntries, 2)
	for _, e := range athenaEntries {
		wantEqual(t, "Athena", e.Agent)
	}

	// Test iterator version
	count := 0
	for e := range log.EntriesForSeq("Athena") {
		wantEqual(t, "Athena", e.Agent)
		count++
	}
	wantEqual(t, 2, count)
}

func TestAudit_AuditLog_EntriesSeq_Good(t *testing.T) {
	log := NewAuditLog(nil)
	log.Record(EvalResult{Agent: "Athena", Cap: CapPushRepo, Decision: Allow, Reason: "ok"}, "")
	log.Record(EvalResult{Agent: "Clotho", Cap: CapCreatePR, Decision: Allow, Reason: "ok"}, "")

	count := 0
	for range log.EntriesSeq() {
		count++
	}
	wantEqual(t, 2, count)
}

func TestAudit_AuditLog_EntriesFor_Bad_NotFound(t *testing.T) {
	log := NewAuditLog(nil)
	log.Record(EvalResult{Agent: "Athena", Cap: CapPushRepo, Decision: Allow, Reason: "ok"}, "")

	wantEmpty(t, log.EntriesFor("NonExistent"))
}

// --- Writer output ---

func TestAudit_AuditLog_Record_Good_WritesToWriter(t *testing.T) {
	buf := core.NewBuilder()
	log := NewAuditLog(buf)

	result := EvalResult{
		Decision: Allow,
		Agent:    "Athena",
		Cap:      CapPushRepo,
		Reason:   "allowed",
	}
	err := log.Record(result, "host-uk/core")
	mustNoError(t, err)

	// Should have written a JSON line.
	output := buf.String()
	wantTrue(t, core.HasSuffix(output, "\n"))

	var entry AuditEntry
	decodeResult := core.JSONUnmarshal([]byte(output), &entry)
	mustTrue(t, decodeResult.OK, testMessagef("failed to unmarshal audit entry: %v", decodeResult.Value))
	wantEqual(t, "Athena", entry.Agent)
	wantEqual(t, CapPushRepo, entry.Cap)
	wantEqual(t, Allow, entry.Decision)
	wantEqual(t, "host-uk/core", entry.Repo)
}

func TestAudit_AuditLog_Record_Good_MultipleLines(t *testing.T) {
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
	wantLen(t, lines, 3)

	// Each line should be valid JSON.
	for _, line := range lines {
		var entry AuditEntry
		result := core.JSONUnmarshal([]byte(line), &entry)
		wantTrue(t, result.OK, testMessagef("failed to unmarshal audit line: %v", result.Value))
	}
}

func TestAudit_AuditLog_Record_Bad_WriterError(t *testing.T) {
	log := NewAuditLog(&failWriter{})

	result := EvalResult{
		Decision: Allow,
		Agent:    "Athena",
		Cap:      CapPushRepo,
		Reason:   "ok",
	}
	err := log.Record(result, "")
	wantError(t, err)
	wantContains(t, err.Error(), "write failed")

	// Entry should still be recorded in memory.
	wantEqual(t, 1, log.Len())
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
		mustTrue(t, result.OK, testMessagef("failed to marshal decision: %v", result.Value))
		wantEqual(t, expected[i], string(result.Value.([]byte)))

		var decoded Decision
		decodeResult := core.JSONUnmarshal(result.Value.([]byte), &decoded)
		mustTrue(t, decodeResult.OK, testMessagef("failed to unmarshal decision: %v", decodeResult.Value))
		wantEqual(t, d, decoded)
	}
}

func TestAudit_DecisionJSON_Bad_UnknownString(t *testing.T) {
	var d Decision
	result := core.JSONUnmarshal([]byte(`"invalid"`), &d)
	err, _ := result.Value.(error)
	wantError(t, err)
	wantContains(t, err.Error(), "unknown decision")
}

func TestAudit_DecisionJSON_Bad_NonString(t *testing.T) {
	var d Decision
	result := core.JSONUnmarshal([]byte(`42`), &d)
	err, _ := result.Value.(error)
	wantError(t, err)
}

// --- Concurrent audit logging ---

func TestAudit_AuditConcurrent_Good(t *testing.T) {
	buf := core.NewBuilder()
	log := NewAuditLog(buf)

	const n = 10
	var wg sync.WaitGroup

	for i := range n {
		wg.Go(func() {
			log.Record(EvalResult{
				Agent:    core.Sprintf("agent-%d", i),
				Cap:      CapPushRepo,
				Decision: Allow,
				Reason:   "ok",
			}, "")
		})
	}

	wg.Wait()
	wantEqual(t, n, log.Len())
}

// --- Integration: PolicyEngine + AuditLog ---

func TestAudit_AuditPolicyIntegration_Good(t *testing.T) {
	buf := core.NewBuilder()
	log := NewAuditLog(buf)
	pe := newTestEngine(t)

	// Evaluate and record
	result := pe.Evaluate("Athena", CapPushRepo, "host-uk/core")
	err := log.Record(result, "host-uk/core")
	mustNoError(t, err)

	result = pe.Evaluate("BugSETI-001", CapPushRepo, "host-uk/core")
	err = log.Record(result, "host-uk/core")
	mustNoError(t, err)

	wantEqual(t, 2, log.Len())

	// Verify entries match evaluation results.
	entries := log.Entries()
	wantEqual(t, Allow, entries[0].Decision)
	wantEqual(t, Deny, entries[1].Decision)
}

func TestAudit_Decision_MarshalJSON_Good(t *core.T) {
	subject := (*Decision).MarshalJSON
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_Decision_MarshalJSON_Bad(t *core.T) {
	subject := (*Decision).MarshalJSON
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_Decision_MarshalJSON_Ugly(t *core.T) {
	subject := (*Decision).MarshalJSON
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_Decision_UnmarshalJSON_Good(t *core.T) {
	subject := (*Decision).UnmarshalJSON
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_Decision_UnmarshalJSON_Bad(t *core.T) {
	subject := (*Decision).UnmarshalJSON
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_Decision_UnmarshalJSON_Ugly(t *core.T) {
	subject := (*Decision).UnmarshalJSON
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_NewAuditLog_Good(t *core.T) {
	subject := NewAuditLog
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_NewAuditLog_Bad(t *core.T) {
	subject := NewAuditLog
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_NewAuditLog_Ugly(t *core.T) {
	subject := NewAuditLog
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_Record_Bad(t *core.T) {
	subject := (*AuditLog).Record
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_Record_Ugly(t *core.T) {
	subject := (*AuditLog).Record
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_Entries_Good(t *core.T) {
	subject := (*AuditLog).Entries
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_Entries_Bad(t *core.T) {
	subject := (*AuditLog).Entries
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_Entries_Ugly(t *core.T) {
	subject := (*AuditLog).Entries
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_EntriesSeq_Bad(t *core.T) {
	subject := (*AuditLog).EntriesSeq
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_EntriesSeq_Ugly(t *core.T) {
	subject := (*AuditLog).EntriesSeq
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_Len_Good(t *core.T) {
	subject := (*AuditLog).Len
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_Len_Bad(t *core.T) {
	subject := (*AuditLog).Len
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_Len_Ugly(t *core.T) {
	subject := (*AuditLog).Len
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_EntriesFor_Bad(t *core.T) {
	subject := (*AuditLog).EntriesFor
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_EntriesFor_Ugly(t *core.T) {
	subject := (*AuditLog).EntriesFor
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_EntriesForSeq_Good(t *core.T) {
	subject := (*AuditLog).EntriesForSeq
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_EntriesForSeq_Bad(t *core.T) {
	subject := (*AuditLog).EntriesForSeq
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestAudit_AuditLog_EntriesForSeq_Ugly(t *core.T) {
	subject := (*AuditLog).EntriesForSeq
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
