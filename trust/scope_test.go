package trust

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- matchScope ---

func TestScope_MatchScope_Good_ExactMatch(t *testing.T) {
	assert.True(t, matchScope("host-uk/core", "host-uk/core"))
}

func TestScope_MatchScope_Good_SingleWildcard(t *testing.T) {
	assert.True(t, matchScope("core/*", "core/php"))
	assert.True(t, matchScope("core/*", "core/go-crypt"))
	assert.True(t, matchScope("host-uk/*", "host-uk/core"))
}

func TestScope_MatchScope_Good_RecursiveWildcard(t *testing.T) {
	assert.True(t, matchScope("core/**", "core/php"))
	assert.True(t, matchScope("core/**", "core/php/sub"))
	assert.True(t, matchScope("core/**", "core/a/b/c"))
}

func TestScope_MatchScope_Bad_ExactMismatch(t *testing.T) {
	assert.False(t, matchScope("host-uk/core", "host-uk/docs"))
}

func TestScope_MatchScope_Bad_SingleWildcardNoNested(t *testing.T) {
	// "core/*" should NOT match "core/php/sub" — only single level.
	assert.False(t, matchScope("core/*", "core/php/sub"))
	assert.False(t, matchScope("core/*", "core/a/b"))
}

func TestScope_MatchScope_Bad_SingleWildcardNoPrefix(t *testing.T) {
	// "core/*" should NOT match "other/php".
	assert.False(t, matchScope("core/*", "other/php"))
}

func TestScope_MatchScope_Bad_RecursiveWildcardNoPrefix(t *testing.T) {
	assert.False(t, matchScope("core/**", "other/php"))
}

func TestScope_MatchScope_Bad_EmptyRepo(t *testing.T) {
	assert.False(t, matchScope("core/*", ""))
}

func TestScope_MatchScope_Bad_WildcardInMiddle(t *testing.T) {
	// Wildcard not at the end — should not match.
	assert.False(t, matchScope("core/*/sub", "core/php/sub"))
}

func TestScope_MatchScope_Bad_WildcardOnlyPrefix(t *testing.T) {
	// "core/*" should not match the prefix itself.
	assert.False(t, matchScope("core/*", "core"))
	assert.False(t, matchScope("core/*", "core/"))
}

func TestScope_MatchScope_Good_RecursiveWildcardSingleLevel(t *testing.T) {
	// "core/**" should also match single-level children.
	assert.True(t, matchScope("core/**", "core/php"))
}

func TestScope_MatchScope_Bad_RecursiveWildcardPrefixOnly(t *testing.T) {
	assert.False(t, matchScope("core/**", "core"))
	assert.False(t, matchScope("core/**", "corefoo"))
}

// --- repoAllowed with wildcards ---

func TestScope_RepoAllowedWildcard_Good(t *testing.T) {
	scoped := []string{"core/*", "host-uk/docs"}
	assert.True(t, repoAllowed(scoped, "core/php"))
	assert.True(t, repoAllowed(scoped, "core/go-crypt"))
	assert.True(t, repoAllowed(scoped, "host-uk/docs"))
}

func TestScope_RepoAllowedWildcard_Good_Recursive(t *testing.T) {
	scoped := []string{"core/**"}
	assert.True(t, repoAllowed(scoped, "core/php"))
	assert.True(t, repoAllowed(scoped, "core/php/sub"))
}

func TestScope_RepoAllowedWildcard_Bad_NoMatch(t *testing.T) {
	scoped := []string{"core/*"}
	assert.False(t, repoAllowed(scoped, "other/repo"))
	assert.False(t, repoAllowed(scoped, "core/php/sub"))
}

func TestScope_RepoAllowedWildcard_Bad_EmptyRepo(t *testing.T) {
	scoped := []string{"core/*"}
	assert.False(t, repoAllowed(scoped, ""))
}

func TestScope_RepoAllowedWildcard_Bad_EmptyScope(t *testing.T) {
	assert.False(t, repoAllowed(nil, "core/php"))
	assert.False(t, repoAllowed([]string{}, "core/php"))
}

// --- Integration: PolicyEngine with wildcard scopes ---

func TestScope_EvaluateWildcardScope_Good_SingleLevel(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{
		Name:        "WildAgent",
		Tier:        TierVerified,
		ScopedRepos: []string{"core/*"},
	}))
	pe := NewPolicyEngine(r)

	result := pe.Evaluate("WildAgent", CapPushRepo, "core/php")
	assert.Equal(t, Allow, result.Decision)

	result = pe.Evaluate("WildAgent", CapPushRepo, "core/go-crypt")
	assert.Equal(t, Allow, result.Decision)
}

func TestScope_EvaluateWildcardScope_Bad_OutOfScope(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{
		Name:        "WildAgent",
		Tier:        TierVerified,
		ScopedRepos: []string{"core/*"},
	}))
	pe := NewPolicyEngine(r)

	result := pe.Evaluate("WildAgent", CapPushRepo, "host-uk/docs")
	assert.Equal(t, Deny, result.Decision)
	assert.Contains(t, result.Reason, "does not have access")
}

func TestScope_EvaluateWildcardScope_Bad_NestedNotAllowedBySingleStar(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{
		Name:        "WildAgent",
		Tier:        TierVerified,
		ScopedRepos: []string{"core/*"},
	}))
	pe := NewPolicyEngine(r)

	result := pe.Evaluate("WildAgent", CapPushRepo, "core/php/sub")
	assert.Equal(t, Deny, result.Decision)
}

func TestScope_EvaluateWildcardScope_Good_RecursiveAllowsNested(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{
		Name:        "DeepAgent",
		Tier:        TierVerified,
		ScopedRepos: []string{"core/**"},
	}))
	pe := NewPolicyEngine(r)

	result := pe.Evaluate("DeepAgent", CapPushRepo, "core/php/sub")
	assert.Equal(t, Allow, result.Decision)
}

func TestScope_EvaluateWildcardScope_Good_MixedExactAndWildcard(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{
		Name:        "MixedAgent",
		Tier:        TierVerified,
		ScopedRepos: []string{"core/*", "host-uk/docs"},
	}))
	pe := NewPolicyEngine(r)

	// Wildcard match
	result := pe.Evaluate("MixedAgent", CapPushRepo, "core/php")
	assert.Equal(t, Allow, result.Decision)

	// Exact match
	result = pe.Evaluate("MixedAgent", CapPushRepo, "host-uk/docs")
	assert.Equal(t, Allow, result.Decision)

	// Neither
	result = pe.Evaluate("MixedAgent", CapPushRepo, "host-uk/core")
	assert.Equal(t, Deny, result.Decision)
}

func TestScope_EvaluateWildcardScope_Good_ReadSecretsScoped(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{
		Name:        "ScopedSecrets",
		Tier:        TierVerified,
		ScopedRepos: []string{"core/*"},
	}))
	pe := NewPolicyEngine(r)

	result := pe.Evaluate("ScopedSecrets", CapReadSecrets, "core/php")
	assert.Equal(t, Allow, result.Decision)

	result = pe.Evaluate("ScopedSecrets", CapReadSecrets, "other/repo")
	assert.Equal(t, Deny, result.Decision)
}
