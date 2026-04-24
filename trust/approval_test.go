package trust

import (
	"sync"
	"testing"

	core "dappco.re/go/core"
)

// --- ApprovalStatus ---

func TestApproval_ApprovalStatusString_Good(t *testing.T) {
	wantEqual(t, "pending", ApprovalPending.String())
	wantEqual(t, "approved", ApprovalApproved.String())
	wantEqual(t, "denied", ApprovalDenied.String())
}

func TestApproval_ApprovalStatusString_Bad_Unknown(t *testing.T) {
	wantContains(t, ApprovalStatus(99).String(), "unknown")
}

// --- Submit ---

func TestApproval_ApprovalSubmit_Good(t *testing.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	mustNoError(t, err)
	wantNotEmpty(t, id)
	wantEqual(t, 1, q.Len())
}

func TestApproval_ApprovalSubmit_Good_MultipleRequests(t *testing.T) {
	q := NewApprovalQueue()
	id1, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	mustNoError(t, err)
	id2, err := q.Submit("Hypnos", CapMergePR, "host-uk/docs")
	mustNoError(t, err)

	wantNotEqual(t, id1, id2, "each request should get a unique ID")
	wantEqual(t, 2, q.Len())
}

func TestApproval_ApprovalSubmit_Good_EmptyRepo(t *testing.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "")
	mustNoError(t, err)
	wantNotEmpty(t, id)

	req := q.Get(id)
	mustNotNil(t, req)
	wantEmpty(t, req.Repo)
}

func TestApproval_ApprovalSubmit_Bad_EmptyAgent(t *testing.T) {
	q := NewApprovalQueue()
	_, err := q.Submit("", CapMergePR, "")
	wantError(t, err)
	wantContains(t, err.Error(), "agent name is required")
}

func TestApproval_ApprovalSubmit_Bad_EmptyCapability(t *testing.T) {
	q := NewApprovalQueue()
	_, err := q.Submit("Clotho", "", "")
	wantError(t, err)
	wantContains(t, err.Error(), "capability is required")
}

// --- Get ---

func TestApproval_ApprovalGet_Good(t *testing.T) {
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

func TestApproval_ApprovalGet_Good_ReturnsSnapshot(t *testing.T) {
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

func TestApproval_ApprovalGet_Bad_NotFound(t *testing.T) {
	q := NewApprovalQueue()
	wantNil(t, q.Get("nonexistent"))
}

// --- Approve ---

func TestApproval_ApprovalApprove_Good(t *testing.T) {
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

func TestApproval_ApprovalApprove_Bad_NotFound(t *testing.T) {
	q := NewApprovalQueue()
	err := q.Approve("nonexistent", "admin", "")
	wantError(t, err)
	wantContains(t, err.Error(), "not found")
}

func TestApproval_ApprovalApprove_Bad_AlreadyApproved(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")
	mustNoError(t, q.Approve(id, "admin", ""))

	err := q.Approve(id, "admin2", "")
	wantError(t, err)
	wantContains(t, err.Error(), "already approved")
}

func TestApproval_ApprovalApprove_Bad_AlreadyDenied(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")
	mustNoError(t, q.Deny(id, "admin", "nope"))

	err := q.Approve(id, "admin2", "")
	wantError(t, err)
	wantContains(t, err.Error(), "already denied")
}

// --- Deny ---

func TestApproval_ApprovalDeny_Good(t *testing.T) {
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

func TestApproval_ApprovalDeny_Bad_NotFound(t *testing.T) {
	q := NewApprovalQueue()
	err := q.Deny("nonexistent", "admin", "")
	wantError(t, err)
	wantContains(t, err.Error(), "not found")
}

func TestApproval_ApprovalDeny_Bad_AlreadyDenied(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")
	mustNoError(t, q.Deny(id, "admin", ""))

	err := q.Deny(id, "admin2", "")
	wantError(t, err)
	wantContains(t, err.Error(), "already denied")
}

// --- Pending ---

func TestApproval_ApprovalPending_Good(t *testing.T) {
	q := NewApprovalQueue()
	q.Submit("Clotho", CapMergePR, "host-uk/core")
	q.Submit("Hypnos", CapMergePR, "host-uk/docs")

	id3, _ := q.Submit("Darbs", CapMergePR, "host-uk/tools")
	q.Approve(id3, "admin", "")

	pending := q.Pending()
	wantLen(t, pending, 2)
}

func TestApproval_ApprovalPending_Good_Empty(t *testing.T) {
	q := NewApprovalQueue()
	wantEmpty(t, q.Pending())
}

func TestApproval_ApprovalPendingSeq_Good(t *testing.T) {
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
	wg.Add(n)

	ids := make([]string, n)
	var mu sync.Mutex

	// Submit concurrently
	for i := range n {
		go func(idx int) {
			defer wg.Done()
			id, err := q.Submit(
				core.Sprintf("agent-%d", idx),
				CapMergePR,
				"host-uk/core",
			)
			wantNoError(t, err)
			mu.Lock()
			ids[idx] = id
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	wantEqual(t, n, q.Len())

	// Approve/deny concurrently
	wg.Add(n)
	for i := range n {
		go func(idx int) {
			defer wg.Done()
			mu.Lock()
			id := ids[idx]
			mu.Unlock()
			if idx%2 == 0 {
				_ = q.Approve(id, "admin", "ok")
			} else {
				_ = q.Deny(id, "admin", "no")
			}
		}(i)
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
