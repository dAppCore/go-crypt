// Package trust implements an agent trust model with tiered access control.
//
// Agents are assigned trust tiers that determine their capabilities:
//
//   - Tier 3 (Full Trust): Internal agents with full access (e.g., Athena, Virgil, Charon)
//   - Tier 2 (Verified): Partner agents with scoped access (e.g., Clotho, Hypnos)
//   - Tier 1 (Untrusted): External/community agents with minimal access
//
// The package provides a Registry for managing agent identities and a PolicyEngine
// for evaluating capability requests against trust policies.
package trust

import (
	"iter"
	"sync" // Note: AX-6 — internal concurrency primitive; structural for trust registry state.
	"time"

	core "dappco.re/go/core"
	coreerr "dappco.re/go/log"
)

// Tier represents an agent's trust level in the system.
// Usage: use Tier with the other exported helpers in this package.
type Tier int

const (
	// TierUntrusted is for external/community agents with minimal access.
	// Usage: compare or pass TierUntrusted when using the related package APIs.
	TierUntrusted Tier = 1
	// TierVerified is for partner agents with scoped access.
	// Usage: compare or pass TierVerified when using the related package APIs.
	TierVerified Tier = 2
	// TierFull is for internal agents with full access.
	// Usage: compare or pass TierFull when using the related package APIs.
	TierFull Tier = 3
)

// String returns the human-readable name of the tier.
// Usage: call String(...) during the package's normal workflow.
func (t Tier) String() string {
	switch t {
	case TierUntrusted:
		return "untrusted"
	case TierVerified:
		return "verified"
	case TierFull:
		return "full"
	default:
		return core.Sprintf("unknown(%d)", int(t))
	}
}

// Valid returns true if the tier is a recognised trust level.
// Usage: call Valid(...) during the package's normal workflow.
func (t Tier) Valid() bool {
	return t >= TierUntrusted && t <= TierFull
}

// Capability represents a specific action an agent can perform.
// Usage: use Capability with the other exported helpers in this package.
type Capability string

const (
	// CapPushRepo allows pushing commits to a repository.
	// Usage: pass CapPushRepo to PolicyEngine.Evaluate or include it in a Policy.
	CapPushRepo Capability = "repo.push"
	// CapMergePR allows merging a pull request.
	// Usage: pass CapMergePR to PolicyEngine.Evaluate or include it in a Policy.
	CapMergePR Capability = "pr.merge"
	// CapCreatePR allows creating a pull request.
	// Usage: pass CapCreatePR to PolicyEngine.Evaluate or include it in a Policy.
	CapCreatePR Capability = "pr.create"
	// CapCreateIssue allows creating an issue.
	// Usage: pass CapCreateIssue to PolicyEngine.Evaluate or include it in a Policy.
	CapCreateIssue Capability = "issue.create"
	// CapCommentIssue allows commenting on an issue.
	// Usage: pass CapCommentIssue to PolicyEngine.Evaluate or include it in a Policy.
	CapCommentIssue Capability = "issue.comment"
	// CapReadSecrets allows reading secret material.
	// Usage: pass CapReadSecrets to PolicyEngine.Evaluate or include it in a Policy.
	CapReadSecrets Capability = "secrets.read"
	// CapRunPrivileged allows running privileged commands.
	// Usage: pass CapRunPrivileged to PolicyEngine.Evaluate or include it in a Policy.
	CapRunPrivileged Capability = "cmd.privileged"
	// CapAccessWorkspace allows accessing the workspace filesystem.
	// Usage: pass CapAccessWorkspace to PolicyEngine.Evaluate or include it in a Policy.
	CapAccessWorkspace Capability = "workspace.access"
	// CapModifyFlows allows modifying workflow definitions.
	// Usage: pass CapModifyFlows to PolicyEngine.Evaluate or include it in a Policy.
	CapModifyFlows Capability = "flows.modify"
)

// Agent represents an agent identity in the trust system.
// Usage: use Agent with the other exported helpers in this package.
type Agent struct {
	// Name is the unique identifier for the agent (e.g., "Athena", "Clotho").
	Name string
	// Tier is the agent's trust level.
	Tier Tier
	// ScopedRepos limits repo access for Tier 2 agents. Empty means no repo access.
	// Tier 3 agents ignore this field (they have access to all repos).
	ScopedRepos []string
	// RateLimit is the maximum requests per minute. 0 means unlimited.
	RateLimit int
	// TokenExpiresAt is when the agent's token expires.
	TokenExpiresAt time.Time
	// CreatedAt is when the agent was registered.
	CreatedAt time.Time
}

// Registry manages agent identities and their trust tiers.
// Usage: use Registry with the other exported helpers in this package.
type Registry struct {
	mu     sync.RWMutex
	agents map[string]*Agent
}

// NewRegistry creates an empty agent registry.
// Usage: call NewRegistry(...) to create a ready-to-use value.
func NewRegistry() *Registry {
	return &Registry{
		agents: make(map[string]*Agent),
	}
}

// Register adds or updates an agent in the registry.
// Returns an error if the agent name is empty or the tier is invalid.
// Usage: call Register(...) during the package's normal workflow.
func (r *Registry) Register(agent Agent) error {
	if agent.Name == "" {
		return coreerr.E("trust.Register", "agent name is required", nil)
	}
	if !agent.Tier.Valid() {
		return coreerr.E("trust.Register", core.Sprintf("invalid tier %d for agent %q", agent.Tier, agent.Name), nil)
	}
	if agent.CreatedAt.IsZero() {
		agent.CreatedAt = time.Now()
	}
	if agent.RateLimit == 0 {
		agent.RateLimit = defaultRateLimit(agent.Tier)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.agents[agent.Name] = &agent
	return nil
}

// Get returns the agent with the given name, or nil if not found.
// Usage: call Get(...) during the package's normal workflow.
func (r *Registry) Get(name string) *Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.agents[name]
}

// Remove deletes an agent from the registry.
// Usage: call Remove(...) during the package's normal workflow.
func (r *Registry) Remove(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.agents[name]; !ok {
		return false
	}
	delete(r.agents, name)
	return true
}

// List returns all registered agents. The returned slice is a snapshot.
// Usage: call List(...) during the package's normal workflow.
func (r *Registry) List() []Agent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Agent, 0, len(r.agents))
	for _, a := range r.agents {
		out = append(out, *a)
	}
	return out
}

// ListSeq returns an iterator over all registered agents.
// Usage: call ListSeq(...) during the package's normal workflow.
func (r *Registry) ListSeq() iter.Seq[Agent] {
	return func(yield func(Agent) bool) {
		r.mu.RLock()
		defer r.mu.RUnlock()
		for _, a := range r.agents {
			if !yield(*a) {
				return
			}
		}
	}
}

// Len returns the number of registered agents.
// Usage: call Len(...) during the package's normal workflow.
func (r *Registry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.agents)
}

// defaultRateLimit returns the default rate limit for a given tier.
func defaultRateLimit(t Tier) int {
	switch t {
	case TierUntrusted:
		return 10
	case TierVerified:
		return 60
	case TierFull:
		return 0 // unlimited
	default:
		return 10
	}
}
