package trust

import (
	"fmt"
	"iter"
	"sync"
	"time"
)

// ApprovalStatus represents the state of an approval request.
type ApprovalStatus int

const (
	// ApprovalPending means the request is awaiting review.
	ApprovalPending ApprovalStatus = iota
	// ApprovalApproved means the request was approved.
	ApprovalApproved
	// ApprovalDenied means the request was denied.
	ApprovalDenied
)

// String returns the human-readable name of the approval status.
func (s ApprovalStatus) String() string {
	switch s {
	case ApprovalPending:
		return "pending"
	case ApprovalApproved:
		return "approved"
	case ApprovalDenied:
		return "denied"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// ApprovalRequest represents a queued capability approval request.
type ApprovalRequest struct {
	// ID is the unique identifier for this request.
	ID string
	// Agent is the name of the requesting agent.
	Agent string
	// Cap is the capability being requested.
	Cap Capability
	// Repo is the optional repo context for repo-scoped capabilities.
	Repo string
	// Status is the current approval status.
	Status ApprovalStatus
	// Reason is a human-readable explanation from the reviewer.
	Reason string
	// RequestedAt is when the request was created.
	RequestedAt time.Time
	// ReviewedAt is when the request was reviewed (zero if pending).
	ReviewedAt time.Time
	// ReviewedBy is the name of the admin who reviewed the request.
	ReviewedBy string
}

// ApprovalQueue manages pending approval requests for NeedsApproval decisions.
type ApprovalQueue struct {
	mu       sync.RWMutex
	requests map[string]*ApprovalRequest
	nextID   int
}

// NewApprovalQueue creates an empty approval queue.
func NewApprovalQueue() *ApprovalQueue {
	return &ApprovalQueue{
		requests: make(map[string]*ApprovalRequest),
	}
}

// Submit creates a new approval request and returns its ID.
// Returns an error if the agent name or capability is empty.
func (q *ApprovalQueue) Submit(agent string, cap Capability, repo string) (string, error) {
	if agent == "" {
		return "", fmt.Errorf("trust.ApprovalQueue.Submit: agent name is required")
	}
	if cap == "" {
		return "", fmt.Errorf("trust.ApprovalQueue.Submit: capability is required")
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	q.nextID++
	id := fmt.Sprintf("approval-%d", q.nextID)

	q.requests[id] = &ApprovalRequest{
		ID:          id,
		Agent:       agent,
		Cap:         cap,
		Repo:        repo,
		Status:      ApprovalPending,
		RequestedAt: time.Now(),
	}

	return id, nil
}

// Approve marks a pending request as approved. Returns an error if the
// request is not found or is not in pending status.
func (q *ApprovalQueue) Approve(id string, reviewedBy string, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	req, ok := q.requests[id]
	if !ok {
		return fmt.Errorf("trust.ApprovalQueue.Approve: request %q not found", id)
	}
	if req.Status != ApprovalPending {
		return fmt.Errorf("trust.ApprovalQueue.Approve: request %q is already %s", id, req.Status)
	}

	req.Status = ApprovalApproved
	req.ReviewedBy = reviewedBy
	req.Reason = reason
	req.ReviewedAt = time.Now()
	return nil
}

// Deny marks a pending request as denied. Returns an error if the
// request is not found or is not in pending status.
func (q *ApprovalQueue) Deny(id string, reviewedBy string, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	req, ok := q.requests[id]
	if !ok {
		return fmt.Errorf("trust.ApprovalQueue.Deny: request %q not found", id)
	}
	if req.Status != ApprovalPending {
		return fmt.Errorf("trust.ApprovalQueue.Deny: request %q is already %s", id, req.Status)
	}

	req.Status = ApprovalDenied
	req.ReviewedBy = reviewedBy
	req.Reason = reason
	req.ReviewedAt = time.Now()
	return nil
}

// Get returns the approval request with the given ID, or nil if not found.
func (q *ApprovalQueue) Get(id string) *ApprovalRequest {
	q.mu.RLock()
	defer q.mu.RUnlock()

	req, ok := q.requests[id]
	if !ok {
		return nil
	}
	// Return a copy to prevent mutation.
	copy := *req
	return &copy
}

// Pending returns all requests with ApprovalPending status.
func (q *ApprovalQueue) Pending() []ApprovalRequest {
	q.mu.RLock()
	defer q.mu.RUnlock()

	var out []ApprovalRequest
	for _, req := range q.requests {
		if req.Status == ApprovalPending {
			out = append(out, *req)
		}
	}
	return out
}

// PendingSeq returns an iterator over all requests with ApprovalPending status.
func (q *ApprovalQueue) PendingSeq() iter.Seq[ApprovalRequest] {
	return func(yield func(ApprovalRequest) bool) {
		q.mu.RLock()
		defer q.mu.RUnlock()

		for _, req := range q.requests {
			if req.Status == ApprovalPending {
				if !yield(*req) {
					return
				}
			}
		}
	}
}

// Len returns the total number of requests in the queue.
func (q *ApprovalQueue) Len() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.requests)
}
