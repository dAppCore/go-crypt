package trust

import (
	"iter"
	"sync" // Note: AX-6 — internal concurrency primitive; structural for approval queue state.
	"time"

	core "dappco.re/go"
	coreerr "dappco.re/go/log"
)

// ApprovalStatus represents the state of an approval request.
// Usage: use ApprovalStatus with the other exported helpers in this package.
type ApprovalStatus int

const (
	// ApprovalPending means the request is awaiting review.
	// Usage: compare or pass ApprovalPending when using the related package APIs.
	ApprovalPending ApprovalStatus = iota
	// ApprovalApproved means the request was approved.
	// Usage: compare or pass ApprovalApproved when using the related package APIs.
	ApprovalApproved
	// ApprovalDenied means the request was denied.
	// Usage: compare or pass ApprovalDenied when using the related package APIs.
	ApprovalDenied
)

// String returns the human-readable name of the approval status.
// Usage: call String(...) during the package's normal workflow.
func (s ApprovalStatus) String() string {
	switch s {
	case ApprovalPending:
		return "pending"
	case ApprovalApproved:
		return "approved"
	case ApprovalDenied:
		return "denied"
	default:
		return core.Sprintf("unknown(%d)", int(s))
	}
}

// ApprovalRequest represents a queued capability approval request.
// Usage: use ApprovalRequest with the other exported helpers in this package.
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
// Usage: use ApprovalQueue with the other exported helpers in this package.
type ApprovalQueue struct {
	mu       sync.RWMutex
	requests map[string]*ApprovalRequest
	nextID   int
}

// NewApprovalQueue creates an empty approval queue.
// Usage: call NewApprovalQueue(...) to create a ready-to-use value.
func NewApprovalQueue() *ApprovalQueue {
	return &ApprovalQueue{
		requests: make(map[string]*ApprovalRequest),
	}
}

// Submit creates a new approval request and returns its ID.
// Returns an error if the agent name or capability is empty.
// Usage: call Submit(...) during the package's normal workflow.
func (q *ApprovalQueue) Submit(agent string, cap Capability, repo string) (string, error) {
	if agent == "" {
		return "", coreerr.E("trust.ApprovalQueue.Submit", "agent name is required", nil)
	}
	if cap == "" {
		return "", coreerr.E("trust.ApprovalQueue.Submit", "capability is required", nil)
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	q.nextID++
	id := core.Sprintf("approval-%d", q.nextID)

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
// Usage: call Approve(...) during the package's normal workflow.
func (q *ApprovalQueue) Approve(id string, reviewedBy string, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	req, ok := q.requests[id]
	if !ok {
		return coreerr.E("trust.ApprovalQueue.Approve", core.Sprintf("request %q not found", id), nil)
	}
	if req.Status != ApprovalPending {
		return coreerr.E("trust.ApprovalQueue.Approve", core.Sprintf("request %q is already %s", id, req.Status), nil)
	}

	req.Status = ApprovalApproved
	req.ReviewedBy = reviewedBy
	req.Reason = reason
	req.ReviewedAt = time.Now()
	return nil
}

// Deny marks a pending request as denied. Returns an error if the
// request is not found or is not in pending status.
// Usage: call Deny(...) during the package's normal workflow.
func (q *ApprovalQueue) Deny(id string, reviewedBy string, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	req, ok := q.requests[id]
	if !ok {
		return coreerr.E("trust.ApprovalQueue.Deny", core.Sprintf("request %q not found", id), nil)
	}
	if req.Status != ApprovalPending {
		return coreerr.E("trust.ApprovalQueue.Deny", core.Sprintf("request %q is already %s", id, req.Status), nil)
	}

	req.Status = ApprovalDenied
	req.ReviewedBy = reviewedBy
	req.Reason = reason
	req.ReviewedAt = time.Now()
	return nil
}

// Get returns the approval request with the given ID, or nil if not found.
// Usage: call Get(...) during the package's normal workflow.
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
// Usage: call Pending(...) during the package's normal workflow.
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
// Usage: call PendingSeq(...) during the package's normal workflow.
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
// Usage: call Len(...) during the package's normal workflow.
func (q *ApprovalQueue) Len() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.requests)
}
