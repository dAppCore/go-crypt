package trust

import (
	"slices"

	core "dappco.re/go/core"
	coreerr "dappco.re/go/log"
)

// Policy defines the access rules for a given trust tier.
// Usage: use Policy with the other exported helpers in this package.
type Policy struct {
	// Tier is the trust level this policy applies to.
	Tier Tier
	// Allowed lists the capabilities granted at this tier.
	Allowed []Capability
	// RequiresApproval lists capabilities that need human/higher-tier approval.
	RequiresApproval []Capability
	// Denied lists explicitly denied capabilities.
	Denied []Capability
}

// PolicyEngine evaluates capability requests against registered policies.
// Usage: use PolicyEngine with the other exported helpers in this package.
type PolicyEngine struct {
	registry *Registry
	policies map[Tier]*Policy
}

// Decision is the result of a policy evaluation.
// Usage: use Decision with the other exported helpers in this package.
type Decision int

const (
	// Deny means the action is not permitted.
	// Usage: compare or pass Deny when using the related package APIs.
	Deny Decision = iota
	// Allow means the action is permitted.
	// Usage: compare or pass Allow when using the related package APIs.
	Allow
	// NeedsApproval means the action requires human or higher-tier approval.
	// Usage: compare or pass NeedsApproval when using the related package APIs.
	NeedsApproval
)

// String returns the human-readable name of the decision.
// Usage: call String(...) during the package's normal workflow.
func (d Decision) String() string {
	switch d {
	case Deny:
		return "deny"
	case Allow:
		return "allow"
	case NeedsApproval:
		return "needs_approval"
	default:
		return core.Sprintf("unknown(%d)", int(d))
	}
}

// EvalResult contains the outcome of a capability evaluation.
// Usage: use EvalResult with the other exported helpers in this package.
type EvalResult struct {
	Decision Decision
	Agent    string
	Cap      Capability
	Reason   string
}

// NewPolicyEngine creates a policy engine with the given registry and default policies.
// Usage: call NewPolicyEngine(...) to create a ready-to-use value.
func NewPolicyEngine(registry *Registry) *PolicyEngine {
	pe := &PolicyEngine{
		registry: registry,
		policies: make(map[Tier]*Policy),
	}
	pe.loadDefaults()
	return pe
}

// Evaluate checks whether the named agent can perform the given capability.
// If the agent has scoped repos and the capability is repo-scoped, the repo
// parameter is checked against the agent's allowed repos.
// Usage: call Evaluate(...) during the package's normal workflow.
func (pe *PolicyEngine) Evaluate(agentName string, cap Capability, repo string) EvalResult {
	agent := pe.registry.Get(agentName)
	if agent == nil {
		return EvalResult{
			Decision: Deny,
			Agent:    agentName,
			Cap:      cap,
			Reason:   "agent not registered",
		}
	}

	policy, ok := pe.policies[agent.Tier]
	if !ok {
		return EvalResult{
			Decision: Deny,
			Agent:    agentName,
			Cap:      cap,
			Reason:   core.Sprintf("no policy for tier %s", agent.Tier),
		}
	}

	// Check explicit denials first.
	if slices.Contains(policy.Denied, cap) {
		return EvalResult{
			Decision: Deny,
			Agent:    agentName,
			Cap:      cap,
			Reason:   core.Sprintf("capability %s is denied for tier %s", cap, agent.Tier),
		}
	}

	// Check if capability requires approval.
	if slices.Contains(policy.RequiresApproval, cap) {
		return EvalResult{
			Decision: NeedsApproval,
			Agent:    agentName,
			Cap:      cap,
			Reason:   core.Sprintf("capability %s requires approval for tier %s", cap, agent.Tier),
		}
	}

	// Check if capability is allowed.
	for _, allowed := range policy.Allowed {
		if allowed == cap {
			// For repo-scoped capabilities, verify repo access.
			if isRepoScoped(cap) && len(agent.ScopedRepos) > 0 {
				if !repoAllowed(agent.ScopedRepos, repo) {
					return EvalResult{
						Decision: Deny,
						Agent:    agentName,
						Cap:      cap,
						Reason:   core.Sprintf("agent %q does not have access to repo %q", agentName, repo),
					}
				}
			}
			return EvalResult{
				Decision: Allow,
				Agent:    agentName,
				Cap:      cap,
				Reason:   core.Sprintf("capability %s allowed for tier %s", cap, agent.Tier),
			}
		}
	}

	return EvalResult{
		Decision: Deny,
		Agent:    agentName,
		Cap:      cap,
		Reason:   core.Sprintf("capability %s not granted for tier %s", cap, agent.Tier),
	}
}

// SetPolicy replaces the policy for a given tier.
// Usage: call SetPolicy(...) during the package's normal workflow.
func (pe *PolicyEngine) SetPolicy(p Policy) error {
	if !p.Tier.Valid() {
		return coreerr.E("trust.SetPolicy", core.Sprintf("invalid tier %d", p.Tier), nil)
	}
	pe.policies[p.Tier] = &p
	return nil
}

// GetPolicy returns the policy for a tier, or nil if none is set.
// Usage: call GetPolicy(...) during the package's normal workflow.
func (pe *PolicyEngine) GetPolicy(t Tier) *Policy {
	return pe.policies[t]
}

// loadDefaults installs the default trust policies from the issue spec.
func (pe *PolicyEngine) loadDefaults() {
	// Tier 3 — Full Trust
	pe.policies[TierFull] = &Policy{
		Tier: TierFull,
		Allowed: []Capability{
			CapPushRepo,
			CapMergePR,
			CapCreatePR,
			CapCreateIssue,
			CapCommentIssue,
			CapReadSecrets,
			CapRunPrivileged,
			CapAccessWorkspace,
			CapModifyFlows,
		},
	}

	// Tier 2 — Verified
	pe.policies[TierVerified] = &Policy{
		Tier: TierVerified,
		Allowed: []Capability{
			CapPushRepo, // scoped to assigned repos
			CapCreatePR, // can create, not merge
			CapCreateIssue,
			CapCommentIssue,
			CapReadSecrets, // scoped to their repos
		},
		RequiresApproval: []Capability{
			CapMergePR,
		},
		Denied: []Capability{
			CapAccessWorkspace, // cannot access other agents' workspaces
			CapModifyFlows,
			CapRunPrivileged,
		},
	}

	// Tier 1 — Untrusted
	pe.policies[TierUntrusted] = &Policy{
		Tier: TierUntrusted,
		Allowed: []Capability{
			CapCreatePR, // fork only, checked at enforcement layer
			CapCommentIssue,
		},
		Denied: []Capability{
			CapPushRepo,
			CapMergePR,
			CapCreateIssue,
			CapReadSecrets,
			CapRunPrivileged,
			CapAccessWorkspace,
			CapModifyFlows,
		},
	}
}

// isRepoScoped returns true if the capability is constrained by repo scope.
func isRepoScoped(cap Capability) bool {
	return core.HasPrefix(string(cap), "repo.") ||
		core.HasPrefix(string(cap), "pr.") ||
		cap == CapReadSecrets
}

// repoAllowed checks if repo is in the agent's scoped list.
// Supports wildcard patterns: "core/*" matches "core/foo" but not "core/foo/bar".
// "core/**" matches "core/foo", "core/foo/bar", etc.
// Exact matches are always checked first.
func repoAllowed(scoped []string, repo string) bool {
	if repo == "" {
		return false
	}
	for _, pattern := range scoped {
		if matchScope(pattern, repo) {
			return true
		}
	}
	return false
}

// matchScope checks if a repo matches a scope pattern.
// Supports exact match, single-level wildcard (*), and recursive wildcard (**).
func matchScope(pattern, repo string) bool {
	// Exact match — fast path.
	if pattern == repo {
		return true
	}

	// Check for wildcard patterns.
	if !core.Contains(pattern, "*") {
		return false
	}

	// "prefix/**" — recursive: matches anything under prefix/.
	if core.HasSuffix(pattern, "/**") {
		prefix := pattern[:len(pattern)-3] // strip "/**"
		if !core.HasPrefix(repo, prefix+"/") {
			return false
		}
		// Must have something after the prefix/.
		return len(repo) > len(prefix)+1
	}

	// "prefix/*" — single level: matches prefix/X but not prefix/X/Y.
	if core.HasSuffix(pattern, "/*") {
		prefix := pattern[:len(pattern)-2] // strip "/*"
		if !core.HasPrefix(repo, prefix+"/") {
			return false
		}
		remainder := repo[len(prefix)+1:]
		// Must have a non-empty name, and no further slashes.
		return remainder != "" && !core.Contains(remainder, "/")
	}

	// Unsupported wildcard position — fall back to no match.
	return false
}
