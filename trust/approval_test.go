package trust

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ApprovalStatus ---

func TestApprovalStatusString_Good(t *testing.T) {
	assert.Equal(t, "pending", ApprovalPending.String())
	assert.Equal(t, "approved", ApprovalApproved.String())
	assert.Equal(t, "denied", ApprovalDenied.String())
}

func TestApprovalStatusString_Bad_Unknown(t *testing.T) {
	assert.Contains(t, ApprovalStatus(99).String(), "unknown")
}

// --- Submit ---

func TestApprovalSubmit_Good(t *testing.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	require.NoError(t, err)
	assert.NotEmpty(t, id)
	assert.Equal(t, 1, q.Len())
}

func TestApprovalSubmit_Good_MultipleRequests(t *testing.T) {
	q := NewApprovalQueue()
	id1, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	require.NoError(t, err)
	id2, err := q.Submit("Hypnos", CapMergePR, "host-uk/docs")
	require.NoError(t, err)

	assert.NotEqual(t, id1, id2, "each request should get a unique ID")
	assert.Equal(t, 2, q.Len())
}

func TestApprovalSubmit_Good_EmptyRepo(t *testing.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "")
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	req := q.Get(id)
	require.NotNil(t, req)
	assert.Empty(t, req.Repo)
}

func TestApprovalSubmit_Bad_EmptyAgent(t *testing.T) {
	q := NewApprovalQueue()
	_, err := q.Submit("", CapMergePR, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "agent name is required")
}

func TestApprovalSubmit_Bad_EmptyCapability(t *testing.T) {
	q := NewApprovalQueue()
	_, err := q.Submit("Clotho", "", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "capability is required")
}

// --- Get ---

func TestApprovalGet_Good(t *testing.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	require.NoError(t, err)

	req := q.Get(id)
	require.NotNil(t, req)
	assert.Equal(t, id, req.ID)
	assert.Equal(t, "Clotho", req.Agent)
	assert.Equal(t, CapMergePR, req.Cap)
	assert.Equal(t, "host-uk/core", req.Repo)
	assert.Equal(t, ApprovalPending, req.Status)
	assert.False(t, req.RequestedAt.IsZero())
	assert.True(t, req.ReviewedAt.IsZero())
}

func TestApprovalGet_Good_ReturnsSnapshot(t *testing.T) {
	q := NewApprovalQueue()
	id, err := q.Submit("Clotho", CapMergePR, "host-uk/core")
	require.NoError(t, err)

	req := q.Get(id)
	require.NotNil(t, req)
	req.Status = ApprovalApproved // Mutate the copy

	// Original should be unchanged.
	original := q.Get(id)
	assert.Equal(t, ApprovalPending, original.Status)
}

func TestApprovalGet_Bad_NotFound(t *testing.T) {
	q := NewApprovalQueue()
	assert.Nil(t, q.Get("nonexistent"))
}

// --- Approve ---

func TestApprovalApprove_Good(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")

	err := q.Approve(id, "admin", "looks good")
	require.NoError(t, err)

	req := q.Get(id)
	require.NotNil(t, req)
	assert.Equal(t, ApprovalApproved, req.Status)
	assert.Equal(t, "admin", req.ReviewedBy)
	assert.Equal(t, "looks good", req.Reason)
	assert.False(t, req.ReviewedAt.IsZero())
}

func TestApprovalApprove_Bad_NotFound(t *testing.T) {
	q := NewApprovalQueue()
	err := q.Approve("nonexistent", "admin", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestApprovalApprove_Bad_AlreadyApproved(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")
	require.NoError(t, q.Approve(id, "admin", ""))

	err := q.Approve(id, "admin2", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already approved")
}

func TestApprovalApprove_Bad_AlreadyDenied(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")
	require.NoError(t, q.Deny(id, "admin", "nope"))

	err := q.Approve(id, "admin2", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already denied")
}

// --- Deny ---

func TestApprovalDeny_Good(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")

	err := q.Deny(id, "admin", "not appropriate")
	require.NoError(t, err)

	req := q.Get(id)
	require.NotNil(t, req)
	assert.Equal(t, ApprovalDenied, req.Status)
	assert.Equal(t, "admin", req.ReviewedBy)
	assert.Equal(t, "not appropriate", req.Reason)
	assert.False(t, req.ReviewedAt.IsZero())
}

func TestApprovalDeny_Bad_NotFound(t *testing.T) {
	q := NewApprovalQueue()
	err := q.Deny("nonexistent", "admin", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestApprovalDeny_Bad_AlreadyDenied(t *testing.T) {
	q := NewApprovalQueue()
	id, _ := q.Submit("Clotho", CapMergePR, "host-uk/core")
	require.NoError(t, q.Deny(id, "admin", ""))

	err := q.Deny(id, "admin2", "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already denied")
}

// --- Pending ---

func TestApprovalPending_Good(t *testing.T) {
	q := NewApprovalQueue()
	q.Submit("Clotho", CapMergePR, "host-uk/core")
	q.Submit("Hypnos", CapMergePR, "host-uk/docs")

	id3, _ := q.Submit("Darbs", CapMergePR, "host-uk/tools")
	q.Approve(id3, "admin", "")

	pending := q.Pending()
	assert.Len(t, pending, 2)
}

func TestApprovalPending_Good_Empty(t *testing.T) {
	q := NewApprovalQueue()
	assert.Empty(t, q.Pending())
}

// --- Concurrent operations ---

func TestApprovalConcurrent_Good(t *testing.T) {
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
				fmt.Sprintf("agent-%d", idx),
				CapMergePR,
				"host-uk/core",
			)
			assert.NoError(t, err)
			mu.Lock()
			ids[idx] = id
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	assert.Equal(t, n, q.Len())

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

	assert.Empty(t, q.Pending())
}

// --- Integration: PolicyEngine + ApprovalQueue ---

func TestApprovalWorkflow_Good_EndToEnd(t *testing.T) {
	pe := newTestEngine(t)
	q := NewApprovalQueue()

	// Clotho (Tier 2) tries to merge a PR — should get NeedsApproval
	result := pe.Evaluate("Clotho", CapMergePR, "host-uk/core")
	assert.Equal(t, NeedsApproval, result.Decision)

	// Submit an approval request
	id, err := q.Submit(result.Agent, result.Cap, "host-uk/core")
	require.NoError(t, err)

	// Admin approves
	err = q.Approve(id, "Virgil", "PR reviewed, merge approved")
	require.NoError(t, err)

	// Verify approval
	req := q.Get(id)
	require.NotNil(t, req)
	assert.Equal(t, ApprovalApproved, req.Status)
	assert.Equal(t, "Virgil", req.ReviewedBy)
}

func TestApprovalWorkflow_Good_DenyEndToEnd(t *testing.T) {
	pe := newTestEngine(t)
	q := NewApprovalQueue()

	result := pe.Evaluate("Clotho", CapMergePR, "host-uk/core")
	assert.Equal(t, NeedsApproval, result.Decision)

	id, err := q.Submit(result.Agent, result.Cap, "host-uk/core")
	require.NoError(t, err)

	err = q.Deny(id, "Virgil", "needs more review")
	require.NoError(t, err)

	req := q.Get(id)
	require.NotNil(t, req)
	assert.Equal(t, ApprovalDenied, req.Status)
}
