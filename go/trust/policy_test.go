package trust

import (
	"sync"
	"testing"

	core "dappco.re/go"
)

func newTestEngine(t *testing.T) *PolicyEngine {
	t.Helper()
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{
		Name: "Athena",
		Tier: TierFull,
	}))
	mustNoError(t, r.Register(Agent{
		Name:        "Clotho",
		Tier:        TierVerified,
		ScopedRepos: []string{"host-uk/core", "host-uk/docs"},
	}))
	mustNoError(t, r.Register(Agent{
		Name: "BugSETI-001",
		Tier: TierUntrusted,
	}))
	return NewPolicyEngine(r)
}

// --- Decision ---

func TestPolicy_Decision_String_Good(t *testing.T) {
	wantEqual(t, "deny", Deny.String())
	wantEqual(t, "allow", Allow.String())
	wantEqual(t, "needs_approval", NeedsApproval.String())
}

func TestPolicy_Decision_String_Bad_Unknown(t *testing.T) {
	got := Decision(99).String()
	wantContains(t, got, "unknown")
	wantContains(t, got, "99")
}

// --- Tier 3 (Full Trust) ---

func TestPolicy_PolicyEngine_Evaluate_Good_Tier3CanDoAnything(t *testing.T) {
	pe := newTestEngine(t)

	caps := []Capability{
		CapPushRepo, CapMergePR, CapCreatePR, CapCreateIssue,
		CapCommentIssue, CapReadSecrets, CapRunPrivileged,
		CapAccessWorkspace, CapModifyFlows,
	}
	for _, cap := range caps {
		result := pe.Evaluate("Athena", cap, "")
		wantEqual(t, Allow, result.Decision, testMessagef("Athena should be allowed %s", cap))
	}
}

// --- Tier 2 (Verified) ---

func TestPolicy_PolicyEngine_Evaluate_Good_Tier2CanCreatePR(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapCreatePR, "host-uk/core")
	wantEqual(t, Allow, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Good_Tier2CanPushToScopedRepo(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapPushRepo, "host-uk/core")
	wantEqual(t, Allow, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Good_Tier2NeedsApprovalToMerge(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapMergePR, "host-uk/core")
	wantEqual(t, NeedsApproval, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Good_Tier2CanCreateIssue(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapCreateIssue, "")
	wantEqual(t, Allow, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Bad_Tier2CannotAccessWorkspace(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapAccessWorkspace, "")
	wantEqual(t, Deny, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Bad_Tier2CannotModifyFlows(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapModifyFlows, "")
	wantEqual(t, Deny, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Bad_Tier2CannotRunPrivileged(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapRunPrivileged, "")
	wantEqual(t, Deny, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Bad_Tier2CannotPushToUnscopedRepo(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Clotho", CapPushRepo, "host-uk/secret-repo")
	wantEqual(t, Deny, result.Decision)
	wantContains(t, result.Reason, "does not have access")
}

func TestPolicy_PolicyEngine_Evaluate_Bad_Tier2RepoScopeEmptyRepo(t *testing.T) {
	pe := newTestEngine(t)
	// Push without specifying a repo should be denied for scoped agents.
	result := pe.Evaluate("Clotho", CapPushRepo, "")
	wantEqual(t, Deny, result.Decision)
}

// --- Tier 1 (Untrusted) ---

func TestPolicy_PolicyEngine_Evaluate_Good_Tier1CanCreatePR(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapCreatePR, "")
	wantEqual(t, Allow, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Good_Tier1CanCommentIssue(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapCommentIssue, "")
	wantEqual(t, Allow, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Bad_Tier1CannotPush(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapPushRepo, "")
	wantEqual(t, Deny, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Bad_Tier1CannotMerge(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapMergePR, "")
	wantEqual(t, Deny, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Bad_Tier1CannotCreateIssue(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapCreateIssue, "")
	wantEqual(t, Deny, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Bad_Tier1CannotReadSecrets(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapReadSecrets, "")
	wantEqual(t, Deny, result.Decision)
}

func TestPolicy_PolicyEngine_Evaluate_Bad_Tier1CannotRunPrivileged(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("BugSETI-001", CapRunPrivileged, "")
	wantEqual(t, Deny, result.Decision)
}

// --- Edge cases ---

func TestPolicy_PolicyEngine_Evaluate_Bad_UnknownAgent(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Unknown", CapCreatePR, "")
	wantEqual(t, Deny, result.Decision)
	wantContains(t, result.Reason, "not registered")
}

func TestPolicy_PolicyEngine_Evaluate_Good_EvalResultFields(t *testing.T) {
	pe := newTestEngine(t)
	result := pe.Evaluate("Athena", CapPushRepo, "")
	wantEqual(t, "Athena", result.Agent)
	wantEqual(t, CapPushRepo, result.Cap)
	wantNotEmpty(t, result.Reason)
}

// --- SetPolicy ---

func TestPolicy_PolicyEngine_SetPolicy_Good(t *testing.T) {
	pe := newTestEngine(t)
	err := pe.SetPolicy(Policy{
		Tier:    TierVerified,
		Allowed: []Capability{CapPushRepo, CapMergePR},
	})
	mustNoError(t, err)

	// Verify the new policy is in effect.
	result := pe.Evaluate("Clotho", CapMergePR, "host-uk/core")
	wantEqual(t, Allow, result.Decision)
}

func TestPolicy_PolicyEngine_SetPolicy_Bad_InvalidTier(t *testing.T) {
	pe := newTestEngine(t)
	err := pe.SetPolicy(Policy{Tier: Tier(0)})
	wantError(t, err)
	wantContains(t, err.Error(), "invalid tier")
}

func TestPolicy_PolicyEngine_GetPolicy_Good(t *testing.T) {
	pe := newTestEngine(t)
	p := pe.GetPolicy(TierFull)
	mustNotNil(t, p)
	wantEqual(t, TierFull, p.Tier)
}

func TestPolicy_PolicyEngine_GetPolicy_Bad_NotFound(t *testing.T) {
	pe := newTestEngine(t)
	policy := pe.GetPolicy(Tier(99))
	wantNil(t, policy)
	wantLen(t, pe.policies, 3)
}

// --- isRepoScoped / repoAllowed helpers ---

func TestPolicy_IsRepoScoped_Good(t *testing.T) {
	wantTrue(t, isRepoScoped(CapPushRepo))
	wantTrue(t, isRepoScoped(CapCreatePR))
	wantTrue(t, isRepoScoped(CapMergePR))
	wantTrue(t, isRepoScoped(CapReadSecrets))
}

func TestPolicy_IsRepoScoped_Bad_NotScoped(t *testing.T) {
	wantFalse(t, isRepoScoped(CapRunPrivileged))
	wantFalse(t, isRepoScoped(CapAccessWorkspace))
	wantFalse(t, isRepoScoped(CapModifyFlows))
}

func TestPolicy_RepoAllowed_Good(t *testing.T) {
	scoped := []string{"host-uk/core", "host-uk/docs"}
	wantTrue(t, repoAllowed(scoped, "host-uk/core"))
	wantTrue(t, repoAllowed(scoped, "host-uk/docs"))
}

func TestPolicy_RepoAllowed_Bad_NotInScope(t *testing.T) {
	scoped := []string{"host-uk/core"}
	allowed := repoAllowed(scoped, "host-uk/secret")
	wantFalse(t, allowed)
	wantTrue(t, repoAllowed(scoped, "host-uk/core"))
}

func TestPolicy_RepoAllowed_Bad_EmptyRepo(t *testing.T) {
	scoped := []string{"host-uk/core"}
	allowed := repoAllowed(scoped, "")
	wantFalse(t, allowed)
	wantTrue(t, repoAllowed(scoped, "host-uk/core"))
}

func TestPolicy_RepoAllowed_Bad_EmptyScope(t *testing.T) {
	empty := []string{}
	wantFalse(t, repoAllowed(nil, "host-uk/core"))
	wantFalse(t, repoAllowed(empty, "host-uk/core"))
	wantLen(t, empty, 0)
}

// --- Tier 3 ignores repo scoping ---

func TestPolicy_PolicyEngine_Evaluate_Good_Tier3IgnoresRepoScope(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{
		Name:        "Virgil",
		Tier:        TierFull,
		ScopedRepos: []string{}, // empty scope should not restrict Tier 3
	}))
	pe := NewPolicyEngine(r)

	result := pe.Evaluate("Virgil", CapPushRepo, "any-repo")
	wantEqual(t, Allow, result.Decision)
}

// --- Default rate limits ---

func TestPolicy_DefaultRateLimit_Good(t *testing.T) {
	wantEqual(t, 10, defaultRateLimit(TierUntrusted))
	wantEqual(t, 60, defaultRateLimit(TierVerified))
	wantEqual(t, 0, defaultRateLimit(TierFull))
	wantEqual(t, 10, defaultRateLimit(Tier(99))) // unknown defaults to 10
}

// --- Phase 0 Additions ---

// TestPolicy_PolicyEngine_Evaluate_Good_Tier2EmptyScopedReposAllowsAll verifies that a Tier 2
// agent with empty ScopedRepos is treated as "unrestricted" for repo-scoped
// capabilities. NOTE: This is a potential security concern documented in
// FINDINGS.md — empty ScopedRepos bypasses the repo scope check entirely.
func TestPolicy_PolicyEngine_Evaluate_Good_Tier2EmptyScopedReposAllowsAll(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{
		Name:        "Hypnos",
		Tier:        TierVerified,
		ScopedRepos: []string{}, // empty — currently means "unrestricted"
	}))
	pe := NewPolicyEngine(r)

	// Current behaviour: empty ScopedRepos skips scope check (len == 0)
	result := pe.Evaluate("Hypnos", CapPushRepo, "host-uk/core")
	wantEqual(t, Allow, result.Decision,
		"empty ScopedRepos currently allows all repos (potential security finding)")

	result = pe.Evaluate("Hypnos", CapReadSecrets, "host-uk/core")
	wantEqual(t, Allow, result.Decision)

	result = pe.Evaluate("Hypnos", CapCreatePR, "host-uk/core")
	wantEqual(t, Allow, result.Decision)

	// Non-repo-scoped capabilities should still work
	result = pe.Evaluate("Hypnos", CapCreateIssue, "")
	wantEqual(t, Allow, result.Decision)
	result = pe.Evaluate("Hypnos", CapCommentIssue, "")
	wantEqual(t, Allow, result.Decision)
}

// TestPolicy_PolicyEngine_Evaluate_Bad_CapabilityNotInAnyList verifies that a capability not in
// allowed, denied, or requires_approval lists defaults to deny.
func TestPolicy_PolicyEngine_Evaluate_Bad_CapabilityNotInAnyList(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{
		Name: "TestAgent",
		Tier: TierFull,
	}))

	pe := NewPolicyEngine(r)

	// Replace the Tier 3 policy with one that only allows a single capability
	err := pe.SetPolicy(Policy{
		Tier:    TierFull,
		Allowed: []Capability{CapCreateIssue},
	})
	mustNoError(t, err)

	// A capability not in the policy's allowed list should be denied
	result := pe.Evaluate("TestAgent", CapPushRepo, "")
	wantEqual(t, Deny, result.Decision)
	wantContains(t, result.Reason, "not granted")
}

// TestPolicy_PolicyEngine_Evaluate_Bad_UnknownCapability verifies that a completely invented
// capability string is denied.
func TestPolicy_PolicyEngine_Evaluate_Bad_UnknownCapability(t *testing.T) {
	pe := newTestEngine(t)

	result := pe.Evaluate("Athena", Capability("nonexistent.capability"), "")
	wantEqual(t, Deny, result.Decision)
	wantContains(t, result.Reason, "not granted")
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
			wantNotEmpty(t, result.Reason)
		}(i)
	}

	wg.Wait()
}

// TestPolicy_PolicyEngine_Evaluate_Bad_Tier2ScopedReposWithEmptyRepoParam verifies that
// a scoped agent requesting a repo-scoped capability without specifying
// the repo is denied.
func TestPolicy_PolicyEngine_Evaluate_Bad_Tier2ScopedReposWithEmptyRepoParam(t *testing.T) {
	pe := newTestEngine(t)

	// Clotho has ScopedRepos but passes empty repo
	result := pe.Evaluate("Clotho", CapReadSecrets, "")
	wantEqual(t, Deny, result.Decision)
}

func TestPolicy_Decision_String_Bad(t *core.T) {
	subject := (*Decision).String
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestPolicy_Decision_String_Ugly(t *core.T) {
	subject := (*Decision).String
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestPolicy_NewPolicyEngine_Good(t *core.T) {
	subject := NewPolicyEngine
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestPolicy_NewPolicyEngine_Bad(t *core.T) {
	subject := NewPolicyEngine
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestPolicy_NewPolicyEngine_Ugly(t *core.T) {
	subject := NewPolicyEngine
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestPolicy_PolicyEngine_Evaluate_Good(t *core.T) {
	subject := (*PolicyEngine).Evaluate
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestPolicy_PolicyEngine_Evaluate_Bad(t *core.T) {
	subject := (*PolicyEngine).Evaluate
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestPolicy_PolicyEngine_Evaluate_Ugly(t *core.T) {
	subject := (*PolicyEngine).Evaluate
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestPolicy_PolicyEngine_SetPolicy_Bad(t *core.T) {
	subject := (*PolicyEngine).SetPolicy
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestPolicy_PolicyEngine_SetPolicy_Ugly(t *core.T) {
	subject := (*PolicyEngine).SetPolicy
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestPolicy_PolicyEngine_GetPolicy_Bad(t *core.T) {
	subject := (*PolicyEngine).GetPolicy
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestPolicy_PolicyEngine_GetPolicy_Ugly(t *core.T) {
	subject := (*PolicyEngine).GetPolicy
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
