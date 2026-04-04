package trust

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestEngine(t *testing.T) *PolicyEngine {
	t.Helper()
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{
		Name: "Athena",
		Tier: TierFull,
	}))
	require.NoError(t, r.Register(Agent{
		Name:        "Clotho",
		Tier:        TierVerified,
		ScopedRepos: []string{"host-uk/core", "host-uk/docs"},
	}))
	require.NoError(t, r.Register(Agent{
		Name: "BugSETI-001",
		Tier: TierUntrusted,
	}))
	return NewPolicyEngine(r)
}

// --- Decision ---

func TestPolicy_DecisionString_Good(t *testing.T) {
	assert.Equal(t, "deny", Deny.String())
	assert.Equal(t, "allow", Allow.String())
	assert.Equal(t, "needs_approval", NeedsApproval.String())
}

func TestPolicy_DecisionString_Bad_Unknown(t *testing.T) {
	assert.Contains(t, Decision(99).String(), "unknown")
}

// --- Tier 3 (Full Trust) ---

func TestPolicy_Evaluate_Good_Tier3CanDoAnything(t *testing.T) {
	pe := newTestEngine(t)

	caps := []Capability{
		CapPushRepo, CapMergePR, CapCreatePR, CapCreateIssue,
		CapCommentIssue, CapReadSecrets, CapRunPrivileged,
		CapAccessWorkspace, CapModifyFlows,
	}
	for _, cap := range caps {
		result := pe.Evaluate("Athena", cap, "")
		assert.Equal(t, Allow, result.Decision, "Athena should be allowed %s", cap)
	}
}

// --- Tier 2 (Verified) ---

func TestPolicy_Evaluate_Good_Tier2CanCreatePR(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapCreatePR, "host-uk/core")
	assert.Equal(t, Allow, result.Decision)
}

func TestPolicy_Evaluate_Good_Tier2CanPushToScopedRepo(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapPushRepo, "host-uk/core")
	assert.Equal(t, Allow, result.Decision)
}

func TestPolicy_Evaluate_Good_Tier2NeedsApprovalToMerge(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapMergePR, "host-uk/core")
	assert.Equal(t, NeedsApproval, result.Decision)
}

func TestPolicy_Evaluate_Good_Tier2CanCreateIssue(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapCreateIssue, "")
	assert.Equal(t, Allow, result.Decision)
}

func TestPolicy_Evaluate_Bad_Tier2CannotAccessWorkspace(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapAccessWorkspace, "")
	assert.Equal(t, Deny, result.Decision)
}

func TestPolicy_Evaluate_Bad_Tier2CannotModifyFlows(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapModifyFlows, "")
	assert.Equal(t, Deny, result.Decision)
}

func TestPolicy_Evaluate_Bad_Tier2CannotRunPrivileged(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapRunPrivileged, "")
	assert.Equal(t, Deny, result.Decision)
}

func TestPolicy_Evaluate_Bad_Tier2CannotPushToUnscopedRepo(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapPushRepo, "host-uk/secret-repo")
	assert.Equal(t, Deny, result.Decision)
	assert.Contains(t, result.Reason, "does not have access")
}

func TestPolicy_Evaluate_Bad_Tier2RepoScopeEmptyRepo(t *testing.T) {
	pe := newTestEngine(t)
	// Push without specifying a repo should be denied for scoped agents.
	result := pe.Evaluate("Clotho", CapPushRepo, "")
	assert.Equal(t, Deny, result.Decision)
}

// --- Tier 1 (Untrusted) ---

func TestPolicy_Evaluate_Good_Tier1CanCreatePR(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapCreatePR, "")
	assert.Equal(t, Allow, result.Decision)
}

func TestPolicy_Evaluate_Good_Tier1CanCommentIssue(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapCommentIssue, "")
	assert.Equal(t, Allow, result.Decision)
}

func TestPolicy_Evaluate_Bad_Tier1CannotPush(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapPushRepo, "")
	assert.Equal(t, Deny, result.Decision)
}

func TestPolicy_Evaluate_Bad_Tier1CannotMerge(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapMergePR, "")
	assert.Equal(t, Deny, result.Decision)
}

func TestPolicy_Evaluate_Bad_Tier1CannotCreateIssue(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapCreateIssue, "")
	assert.Equal(t, Deny, result.Decision)
}

func TestPolicy_Evaluate_Bad_Tier1CannotReadSecrets(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapReadSecrets, "")
	assert.Equal(t, Deny, result.Decision)
}

func TestPolicy_Evaluate_Bad_Tier1CannotRunPrivileged(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapRunPrivileged, "")
	assert.Equal(t, Deny, result.Decision)
}

// --- Edge cases ---

func TestPolicy_Evaluate_Bad_UnknownAgent(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Unknown", CapCreatePR, "")
	assert.Equal(t, Deny, result.Decision)
	assert.Contains(t, result.Reason, "not registered")
}

func TestPolicy_Evaluate_Good_EvalResultFields(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Athena", CapPushRepo, "")
	assert.Equal(t, "Athena", result.Agent)
	assert.Equal(t, CapPushRepo, result.Cap)
	assert.NotEmpty(t, result.Reason)
}

// --- SetPolicy ---

func TestPolicy_SetPolicy_Good(t *testing.T) {
	pe := newTestEngine(t)
	err := pe.SetPolicy(Policy{
		Tier:    TierVerified,
		Allowed: []Capability{CapPushRepo, CapMergePR},
	})
	require.NoError(t, err)

	// Verify the new policy is in effect.
	result := pe.Evaluate("Clotho", CapMergePR, "host-uk/core")
	assert.Equal(t, Allow, result.Decision)
}

func TestPolicy_SetPolicy_Bad_InvalidTier(t *testing.T) {
	pe := newTestEngine(t)
	err := pe.SetPolicy(Policy{Tier: Tier(0)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tier")
}

func TestPolicy_GetPolicy_Good(t *testing.T) {
	pe := newTestEngine(t)
	p := pe.GetPolicy(TierFull)
	require.NotNil(t, p)
	assert.Equal(t, TierFull, p.Tier)
}

func TestPolicy_GetPolicy_Bad_NotFound(t *testing.T) {
	pe := newTestEngine(t)
	assert.Nil(t, pe.GetPolicy(Tier(99)))
}

// --- isRepoScoped / repoAllowed helpers ---

func TestPolicy_IsRepoScoped_Good(t *testing.T) {
	assert.True(t, isRepoScoped(CapPushRepo))
	assert.True(t, isRepoScoped(CapCreatePR))
	assert.True(t, isRepoScoped(CapMergePR))
	assert.True(t, isRepoScoped(CapReadSecrets))
}

func TestPolicy_IsRepoScoped_Bad_NotScoped(t *testing.T) {
	assert.False(t, isRepoScoped(CapRunPrivileged))
	assert.False(t, isRepoScoped(CapAccessWorkspace))
	assert.False(t, isRepoScoped(CapModifyFlows))
}

func TestPolicy_RepoAllowed_Good(t *testing.T) {
	scoped := []string{"host-uk/core", "host-uk/docs"}
	assert.True(t, repoAllowed(scoped, "host-uk/core"))
	assert.True(t, repoAllowed(scoped, "host-uk/docs"))
}

func TestPolicy_RepoAllowed_Bad_NotInScope(t *testing.T) {
	scoped := []string{"host-uk/core"}
	assert.False(t, repoAllowed(scoped, "host-uk/secret"))
}

func TestPolicy_RepoAllowed_Bad_EmptyRepo(t *testing.T) {
	scoped := []string{"host-uk/core"}
	assert.False(t, repoAllowed(scoped, ""))
}

func TestPolicy_RepoAllowed_Bad_EmptyScope(t *testing.T) {
	assert.False(t, repoAllowed(nil, "host-uk/core"))
	assert.False(t, repoAllowed([]string{}, "host-uk/core"))
}

// --- Tier 3 ignores repo scoping ---

func TestPolicy_Evaluate_Good_Tier3IgnoresRepoScope(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{
		Name:        "Virgil",
		Tier:        TierFull,
		ScopedRepos: []string{}, // empty scope should not restrict Tier 3
	}))
	pe := NewPolicyEngine(r)

	result := pe.Evaluate("Virgil", CapPushRepo, "any-repo")
	assert.Equal(t, Allow, result.Decision)
}

// --- Default rate limits ---

func TestPolicy_DefaultRateLimit_Good(t *testing.T) {
	assert.Equal(t, 10, defaultRateLimit(TierUntrusted))
	assert.Equal(t, 60, defaultRateLimit(TierVerified))
	assert.Equal(t, 0, defaultRateLimit(TierFull))
	assert.Equal(t, 10, defaultRateLimit(Tier(99))) // unknown defaults to 10
}

// --- Phase 0 Additions ---

// TestPolicy_Evaluate_Good_Tier2EmptyScopedReposAllowsAll verifies that a Tier 2
// agent with empty ScopedRepos is treated as "unrestricted" for repo-scoped
// capabilities. NOTE: This is a potential security concern documented in
// FINDINGS.md — empty ScopedRepos bypasses the repo scope check entirely.
func TestPolicy_Evaluate_Good_Tier2EmptyScopedReposAllowsAll(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{
		Name:        "Hypnos",
		Tier:        TierVerified,
		ScopedRepos: []string{}, // empty — currently means "unrestricted"
	}))
	pe := NewPolicyEngine(r)

	// Current behaviour: empty ScopedRepos skips scope check (len == 0)
	result := pe.Evaluate("Hypnos", CapPushRepo, "host-uk/core")
	assert.Equal(t, Allow, result.Decision,
		"empty ScopedRepos currently allows all repos (potential security finding)")

	result = pe.Evaluate("Hypnos", CapReadSecrets, "host-uk/core")
	assert.Equal(t, Allow, result.Decision)

	result = pe.Evaluate("Hypnos", CapCreatePR, "host-uk/core")
	assert.Equal(t, Allow, result.Decision)

	// Non-repo-scoped capabilities should still work
	result = pe.Evaluate("Hypnos", CapCreateIssue, "")
	assert.Equal(t, Allow, result.Decision)
	result = pe.Evaluate("Hypnos", CapCommentIssue, "")
	assert.Equal(t, Allow, result.Decision)
}

// TestPolicy_Evaluate_Bad_CapabilityNotInAnyList verifies that a capability not in
// allowed, denied, or requires_approval lists defaults to deny.
func TestPolicy_Evaluate_Bad_CapabilityNotInAnyList(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{
		Name: "TestAgent",
		Tier: TierFull,
	}))

	pe := NewPolicyEngine(r)

	// Replace the Tier 3 policy with one that only allows a single capability
	err := pe.SetPolicy(Policy{
		Tier:    TierFull,
		Allowed: []Capability{CapCreateIssue},
	})
	require.NoError(t, err)

	// A capability not in the policy's allowed list should be denied
	result := pe.Evaluate("TestAgent", CapPushRepo, "")
	assert.Equal(t, Deny, result.Decision)
	assert.Contains(t, result.Reason, "not granted")
}

// TestPolicy_Evaluate_Bad_UnknownCapability verifies that a completely invented
// capability string is denied.
func TestPolicy_Evaluate_Bad_UnknownCapability(t *testing.T) {
	pe := newTestEngine(t)

	result := pe.Evaluate("Athena", Capability("nonexistent.capability"), "")
	assert.Equal(t, Deny, result.Decision)
	assert.Contains(t, result.Reason, "not granted")
}

// TestPolicy_ConcurrentEvaluate_Good verifies that concurrent policy evaluations
// with 10 goroutines do not race.
func TestPolicy_ConcurrentEvaluate_Good(t *testing.T) {
	pe := newTestEngine(t)

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)

	for i := range n {
		go func(idx int) {
			defer wg.Done()
			agents := []string{"Athena", "Clotho", "BugSETI-001"}
			caps := []Capability{CapPushRepo, CapCreatePR, CapCommentIssue}

			agent := agents[idx%len(agents)]
			cap := caps[idx%len(caps)]
			result := pe.Evaluate(agent, cap, "host-uk/core")
			assert.NotEmpty(t, result.Reason)
		}(i)
	}

	wg.Wait()
}

// TestPolicy_Evaluate_Bad_Tier2ScopedReposWithEmptyRepoParam verifies that
// a scoped agent requesting a repo-scoped capability without specifying
// the repo is denied.
func TestPolicy_Evaluate_Bad_Tier2ScopedReposWithEmptyRepoParam(t *testing.T) {
	pe := newTestEngine(t)

	// Clotho has ScopedRepos but passes empty repo
	result := pe.Evaluate("Clotho", CapReadSecrets, "")
	assert.Equal(t, Deny, result.Decision)
}
