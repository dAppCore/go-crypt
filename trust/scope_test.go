package trust

import (
	"testing"
)

// --- matchScope ---

func TestScope_MatchScope_Good_ExactMatch(t *testing.T) {
	wantTrue(t, matchScope("host-uk/core", "host-uk/core"))
}

func TestScope_MatchScope_Good_SingleWildcard(t *testing.T) {
	wantTrue(t, matchScope("core/*", "core/php"))
	wantTrue(t, matchScope("core/*", "core/go-crypt"))
	wantTrue(t, matchScope("host-uk/*", "host-uk/core"))
}

func TestScope_MatchScope_Good_RecursiveWildcard(t *testing.T) {
	wantTrue(t, matchScope("core/**", "core/php"))
	wantTrue(t, matchScope("core/**", "core/php/sub"))
	wantTrue(t, matchScope("core/**", "core/a/b/c"))
}

func TestScope_MatchScope_Bad_ExactMismatch(t *testing.T) {
	wantFalse(t, matchScope("host-uk/core", "host-uk/docs"))
}

func TestScope_MatchScope_Bad_SingleWildcardNoNested(t *testing.T) {
	// "core/*" should NOT match "core/php/sub" — only single level.
	wantFalse(t, matchScope("core/*", "core/php/sub"))
	wantFalse(t, matchScope("core/*", "core/a/b"))
}

func TestScope_MatchScope_Bad_SingleWildcardNoPrefix(t *testing.T) {
	// "core/*" should NOT match "other/php".
	wantFalse(t, matchScope("core/*", "other/php"))
}

func TestScope_MatchScope_Bad_RecursiveWildcardNoPrefix(t *testing.T) {
	wantFalse(t, matchScope("core/**", "other/php"))
}

func TestScope_MatchScope_Bad_EmptyRepo(t *testing.T) {
	wantFalse(t, matchScope("core/*", ""))
}

func TestScope_MatchScope_Bad_WildcardInMiddle(t *testing.T) {
	// Wildcard not at the end — should not match.
	wantFalse(t, matchScope("core/*/sub", "core/php/sub"))
}

func TestScope_MatchScope_Bad_WildcardOnlyPrefix(t *testing.T) {
	// "core/*" should not match the prefix itself.
	wantFalse(t, matchScope("core/*", "core"))
	wantFalse(t, matchScope("core/*", "core/"))
}

func TestScope_MatchScope_Good_RecursiveWildcardSingleLevel(t *testing.T) {
	// "core/**" should also match single-level children.
	wantTrue(t, matchScope("core/**", "core/php"))
}

func TestScope_MatchScope_Bad_RecursiveWildcardPrefixOnly(t *testing.T) {
	wantFalse(t, matchScope("core/**", "core"))
	wantFalse(t, matchScope("core/**", "corefoo"))
}

// --- repoAllowed with wildcards ---

func TestScope_RepoAllowedWildcard_Good(t *testing.T) {
	scoped := []string{"core/*", "host-uk/docs"}
	wantTrue(t, repoAllowed(scoped, "core/php"))
	wantTrue(t, repoAllowed(scoped, "core/go-crypt"))
	wantTrue(t, repoAllowed(scoped, "host-uk/docs"))
}

func TestScope_RepoAllowedWildcard_Good_Recursive(t *testing.T) {
	scoped := []string{"core/**"}
	wantTrue(t, repoAllowed(scoped, "core/php"))
	wantTrue(t, repoAllowed(scoped, "core/php/sub"))
}

func TestScope_RepoAllowedWildcard_Bad_NoMatch(t *testing.T) {
	scoped := []string{"core/*"}
	wantFalse(t, repoAllowed(scoped, "other/repo"))
	wantFalse(t, repoAllowed(scoped, "core/php/sub"))
}

func TestScope_RepoAllowedWildcard_Bad_EmptyRepo(t *testing.T) {
	scoped := []string{"core/*"}
	wantFalse(t, repoAllowed(scoped, ""))
}

func TestScope_RepoAllowedWildcard_Bad_EmptyScope(t *testing.T) {
	wantFalse(t, repoAllowed(nil, "core/php"))
	wantFalse(t, repoAllowed([]string{}, "core/php"))
}

// --- Integration: PolicyEngine with wildcard scopes ---

func TestScope_EvaluateWildcardScope_Good_SingleLevel(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{
		Name:        "WildAgent",
		Tier:        TierVerified,
		ScopedRepos: []string{"core/*"},
	}))
	pe := NewPolicyEngine(r)

	result := pe.Evaluate("WildAgent", CapPushRepo, "core/php")
	wantEqual(t, Allow, result.Decision)

	result = pe.Evaluate("WildAgent", CapPushRepo, "core/go-crypt")
	wantEqual(t, Allow, result.Decision)
}

func TestScope_EvaluateWildcardScope_Bad_OutOfScope(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{
		Name:        "WildAgent",
		Tier:        TierVerified,
		ScopedRepos: []string{"core/*"},
	}))
	pe := NewPolicyEngine(r)

	result := pe.Evaluate("WildAgent", CapPushRepo, "host-uk/docs")
	wantEqual(t, Deny, result.Decision)
	wantContains(t, result.Reason, "does not have access")
}

func TestScope_EvaluateWildcardScope_Bad_NestedNotAllowedBySingleStar(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{
		Name:        "WildAgent",
		Tier:        TierVerified,
		ScopedRepos: []string{"core/*"},
	}))
	pe := NewPolicyEngine(r)

	result := pe.Evaluate("WildAgent", CapPushRepo, "core/php/sub")
	wantEqual(t, Deny, result.Decision)
}

func TestScope_EvaluateWildcardScope_Good_RecursiveAllowsNested(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{
		Name:        "DeepAgent",
		Tier:        TierVerified,
		ScopedRepos: []string{"core/**"},
	}))
	pe := NewPolicyEngine(r)

	result := pe.Evaluate("DeepAgent", CapPushRepo, "core/php/sub")
	wantEqual(t, Allow, result.Decision)
}

func TestScope_EvaluateWildcardScope_Good_MixedExactAndWildcard(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{
		Name:        "MixedAgent",
		Tier:        TierVerified,
		ScopedRepos: []string{"core/*", "host-uk/docs"},
	}))
	pe := NewPolicyEngine(r)

	// Wildcard match
	result := pe.Evaluate("MixedAgent", CapPushRepo, "core/php")
	wantEqual(t, Allow, result.Decision)

	// Exact match
	result = pe.Evaluate("MixedAgent", CapPushRepo, "host-uk/docs")
	wantEqual(t, Allow, result.Decision)

	// Neither
	result = pe.Evaluate("MixedAgent", CapPushRepo, "host-uk/core")
	wantEqual(t, Deny, result.Decision)
}

func TestScope_EvaluateWildcardScope_Good_ReadSecretsScoped(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{
		Name:        "ScopedSecrets",
		Tier:        TierVerified,
		ScopedRepos: []string{"core/*"},
	}))
	pe := NewPolicyEngine(r)

	result := pe.Evaluate("ScopedSecrets", CapReadSecrets, "core/php")
	wantEqual(t, Allow, result.Decision)

	result = pe.Evaluate("ScopedSecrets", CapReadSecrets, "other/repo")
	wantEqual(t, Deny, result.Decision)
}
