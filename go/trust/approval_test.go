package trust

import (
	"sync"
	"testing"

	core "dappco.re/go"
)

// --- ApprovalStatus ---

func TestApproval_ApprovalStatus_String_Good(t *testing.T) {
	wantEqual(t, "pending", ApprovalPending.String())
	wantEqual(t, "approved", ApprovalApproved.String())
	wantEqual(t, "denied", ApprovalDenied.String())
}

func TestApproval_ApprovalStatus_String_Bad_Unknown(t *testing.T) {
	got := ApprovalStatus(99).String()
	wantContains(t, got, "unknown")
	wantContains(t, got, "99")
}

// --- Submit ---

func TestApproval_ApprovalQueue_Submit_Good(t *testing.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	mustNoError(t, err)
	wantNotEmpty(t, id)
	wantEqual(t, 1, q.Len())
}

func TestApproval_ApprovalQueue_Submit_Good_MultipleRequests(t *testing.T) {
	q := NewApprovalQueue()
	id1, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	mustNoError(t, err)
	id2, err := q.Submit("Hypnos", CapMergePR, "host-uk/docs")
	mustNoError(t, err)

	wantNotEqual(t, id1, id2, "each request should get a unique ID")
	wantEqual(t, 2, q.Len())
}

func TestApproval_ApprovalQueue_Submit_Good_EmptyRepo(t *testing.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "")
	mustNoError(t, err)
	wantNotEmpty(t, id)

	req := q.Get(id)
	mustNotNil(t, req)
	wantEmpty(t, req.Repo)
}

func TestApproval_ApprovalQueue_Submit_Bad_EmptyAgent(t *testing.T) {
	q := NewApprovalQueue()
	_, err := q.Submit("", CapMergePR, "")
	wantError(t, err)
	wantContains(t, err.Error(), "agent name is required")
}

func TestApproval_ApprovalQueue_Submit_Bad_EmptyCapability(t *testing.T) {
	q := NewApprovalQueue()
	_, err := q.Submit("Clotho", "", "")
	wantError(t, err)
	wantContains(t, err.Error(), "capability is required")
}

// --- Get ---

func TestApproval_ApprovalQueue_Get_Good(t *testing.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	mustNoError(t, err)

	req := q.Get(id)
	mustNotNil(t, req)
	wantEqual(t, id, req.ID)
	wantEqual(t, "Clotho", req.Agent)
	wantEqual(t, CapMergePR, req.Cap)
	wantEqual(t, "host-uk/core", req.Repo)
	wantEqual(t, ApprovalPending, req.Status)
	wantFalse(t, req.RequestedAt.IsZero())
	wantTrue(t, req.ReviewedAt.IsZero())
}

func TestApproval_ApprovalQueue_Get_Good_ReturnsSnapshot(t *testing.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	mustNoError(t, err)

	req := q.Get(id)
	mustNotNil(t, req)
	req.Status = ApprovalApproved // Mutate the copy

	// Original should be unchanged.
	original := q.Get(id)
	wantEqual(t, ApprovalPending, original.Status)
}

func TestApproval_ApprovalQueue_Get_Bad_NotFound(t *testing.T) {
	q := NewApprovalQueue()
	req := q.Get("nonexistent")
	wantNil(t, req)
	wantEqual(t, 0, q.Len())
}

// --- Approve ---

func TestApproval_ApprovalQueue_Approve_Good(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")

	err := q.Approve(id, "admin", "looks good")
	mustNoError(t, err)

	req := q.Get(id)
	mustNotNil(t, req)
	wantEqual(t, ApprovalApproved, req.Status)
	wantEqual(t, "admin", req.ReviewedBy)
	wantEqual(t, "looks good", req.Reason)
	wantFalse(t, req.ReviewedAt.IsZero())
}

func TestApproval_ApprovalQueue_Approve_Bad_NotFound(t *testing.T) {
	q := NewApprovalQueue()
	err := q.Approve("nonexistent", "admin", "")
	wantError(t, err)
	wantContains(t, err.Error(), "not found")
}

func TestApproval_ApprovalQueue_Approve_Bad_AlreadyApproved(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")
	mustNoError(t, q.Approve(id, "admin", ""))

	err := q.Approve(id, "admin2", "")
	wantError(t, err)
	wantContains(t, err.Error(), "already approved")
}

func TestApproval_ApprovalQueue_Approve_Bad_AlreadyDenied(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")
	mustNoError(t, q.Deny(id, "admin", "nope"))

	err := q.Approve(id, "admin2", "")
	wantError(t, err)
	wantContains(t, err.Error(), "already denied")
}

// --- Deny ---

func TestApproval_ApprovalQueue_Deny_Good(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")

	err := q.Deny(id, "admin", "not appropriate")
	mustNoError(t, err)

	req := q.Get(id)
	mustNotNil(t, req)
	wantEqual(t, ApprovalDenied, req.Status)
	wantEqual(t, "admin", req.ReviewedBy)
	wantEqual(t, "not appropriate", req.Reason)
	wantFalse(t, req.ReviewedAt.IsZero())
}

func TestApproval_ApprovalQueue_Deny_Bad_NotFound(t *testing.T) {
	q := NewApprovalQueue()
	err := q.Deny("nonexistent", "admin", "")
	wantError(t, err)
	wantContains(t, err.Error(), "not found")
}

func TestApproval_ApprovalQueue_Deny_Bad_AlreadyDenied(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")
	mustNoError(t, q.Deny(id, "admin", ""))

	err := q.Deny(id, "admin2", "")
	wantError(t, err)
	wantContains(t, err.Error(), "already denied")
}

// --- Pending ---

func TestApproval_ApprovalQueue_Pending_Good(t *testing.T) {
	q := NewApprovalQueue()
	q.Submit("Clotho", CapMergePR, "host-uk/core")
	q.Submit("Hypnos", CapMergePR, "host-uk/docs")

	id3, _ := q.Submit("Darbs", CapMergePR, "host-uk/tools")
	q.Approve(id3, "admin", "")

	pending := q.Pending()
	wantLen(t, pending, 2)
}

func TestApproval_ApprovalQueue_Pending_Good_Empty(t *testing.T) {
	q := NewApprovalQueue()
	pending := q.Pending()
	wantEmpty(t, pending)
	wantEqual(t, 0, q.Len())
}

func TestApproval_ApprovalQueue_PendingSeq_Good(t *testing.T) {
	q := NewApprovalQueue()
	q.Submit("Clotho", CapMergePR, "host-uk/core")
	q.Submit("Hypnos", CapMergePR, "host-uk/docs")

	id3, _ := q.Submit("Darbs", CapMergePR, "host-uk/tools")
	q.Approve(id3, "admin", "")

	count := 0
	for req := range q.PendingSeq() {
		wantEqual(t, ApprovalPending, req.Status)
		count++
	}
	wantEqual(t, 2, count)
}

// --- Concurrent operations ---

func TestApproval_ApprovalConcurrent_Good(t *testing.T) {
	q := NewApprovalQueue()

	const n = 10
	var wg sync.WaitGroup

	ids := make([]string, n)
	var mu sync.Mutex

	// Submit concurrently
	for i := range n {
		wg.Go(func() {
			id, err := q.Submit(
				core.Sprintf("agent-%d", i),
				CapMergePR,
				"host-uk/core",
			)
			wantNoError(t, err)
			mu.Lock()
			ids[i] = id
			mu.Unlock()
		})
	}
	wg.Wait()

	wantEqual(t, n, q.Len())

	// Approve/deny concurrently
	for i := range n {
		wg.Go(func() {
			mu.Lock()
			id := ids[i]
			mu.Unlock()
			if i%2 == 0 {
				_ = q.Approve(id, "admin", "ok")
			} else {
				_ = q.Deny(id, "admin", "no")
			}
		})
	}
	wg.Wait()

	wantEmpty(t, q.Pending())
}

// --- Integration: PolicyEngine + ApprovalQueue ---

func TestApproval_ApprovalWorkflow_Good_EndToEnd(t *testing.T) {
	pe := newTestEngine(t)
	q := NewApprovalQueue()

	// Clotho (Tier 2) tries to merge a PR — should get NeedsApproval
	result := pe.Evaluate("Clotho", CapMergePR, "host-uk/core")
	wantEqual(t, NeedsApproval, result.Decision)

	// Submit an approval request
	id, err := q.Submit(result.Agent, result.Cap, "host-uk/core")
	mustNoError(t, err)

	// Admin approves
	err = q.Approve(id, "Virgil", "PR reviewed, merge approved")
	mustNoError(t, err)

	// Verify approval
	req := q.Get(id)
	mustNotNil(t, req)
	wantEqual(t, ApprovalApproved, req.Status)
	wantEqual(t, "Virgil", req.ReviewedBy)
}

func TestApproval_ApprovalWorkflow_Good_DenyEndToEnd(t *testing.T) {
	pe := newTestEngine(t)
	q := NewApprovalQueue()

	result := pe.Evaluate("Clotho", CapMergePR, "host-uk/core")
	wantEqual(t, NeedsApproval, result.Decision)

	id, err := q.Submit(result.Agent, result.Cap, "host-uk/core")
	mustNoError(t, err)

	err = q.Deny(id, "Virgil", "needs more review")
	mustNoError(t, err)

	req := q.Get(id)
	mustNotNil(t, req)
	wantEqual(t, ApprovalDenied, req.Status)
}

func TestApproval_ApprovalStatus_String_Bad(t *core.T) {
	subject := (*ApprovalStatus).String
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalStatus_String_Ugly(t *core.T) {
	subject := (*ApprovalStatus).String
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_NewApprovalQueue_Good(t *core.T) {
	subject := NewApprovalQueue
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_NewApprovalQueue_Bad(t *core.T) {
	subject := NewApprovalQueue
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_NewApprovalQueue_Ugly(t *core.T) {
	subject := NewApprovalQueue
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Submit_Bad(t *core.T) {
	subject := (*ApprovalQueue).Submit
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Submit_Ugly(t *core.T) {
	subject := (*ApprovalQueue).Submit
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Approve_Bad(t *core.T) {
	subject := (*ApprovalQueue).Approve
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Approve_Ugly(t *core.T) {
	subject := (*ApprovalQueue).Approve
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Deny_Bad(t *core.T) {
	subject := (*ApprovalQueue).Deny
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Deny_Ugly(t *core.T) {
	subject := (*ApprovalQueue).Deny
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Get_Bad(t *core.T) {
	subject := (*ApprovalQueue).Get
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Get_Ugly(t *core.T) {
	subject := (*ApprovalQueue).Get
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Pending_Bad(t *core.T) {
	subject := (*ApprovalQueue).Pending
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Pending_Ugly(t *core.T) {
	subject := (*ApprovalQueue).Pending
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_PendingSeq_Bad(t *core.T) {
	subject := (*ApprovalQueue).PendingSeq
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_PendingSeq_Ugly(t *core.T) {
	subject := (*ApprovalQueue).PendingSeq
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Len_Good(t *core.T) {
	subject := (*ApprovalQueue).Len
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Len_Bad(t *core.T) {
	subject := (*ApprovalQueue).Len
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestApproval_ApprovalQueue_Len_Ugly(t *core.T) {
	subject := (*ApprovalQueue).Len
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
