package trust

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validPolicyJSON = `{
  "policies": [
    {
      "tier": 3,
      "allowed": ["repo.push", "pr.merge", "pr.create"]
    },
    {
      "tier": 2,
      "allowed": ["pr.create", "issue.create"],
      "requires_approval": ["pr.merge"],
      "denied": ["cmd.privileged"]
    },
    {
      "tier": 1,
      "allowed": ["issue.comment"],
      "denied": ["repo.push", "pr.merge"]
    }
  ]
}`

// --- LoadPolicies ---

func TestLoadPolicies_Good(t *testing.T) {
	policies, err := LoadPolicies(strings.NewReader(validPolicyJSON))
	require.NoError(t, err)
	assert.Len(t, policies, 3)
}

func TestLoadPolicies_Good_FieldMapping(t *testing.T) {
	policies, err := LoadPolicies(strings.NewReader(validPolicyJSON))
	require.NoError(t, err)

	// Tier 3
	assert.Equal(t, TierFull, policies[0].Tier)
	assert.Len(t, policies[0].Allowed, 3)
	assert.Contains(t, policies[0].Allowed, CapPushRepo)
	assert.Nil(t, policies[0].RequiresApproval)
	assert.Nil(t, policies[0].Denied)

	// Tier 2
	assert.Equal(t, TierVerified, policies[1].Tier)
	assert.Len(t, policies[1].Allowed, 2)
	assert.Len(t, policies[1].RequiresApproval, 1)
	assert.Equal(t, CapMergePR, policies[1].RequiresApproval[0])
	assert.Len(t, policies[1].Denied, 1)

	// Tier 1
	assert.Equal(t, TierUntrusted, policies[2].Tier)
	assert.Len(t, policies[2].Allowed, 1)
	assert.Len(t, policies[2].Denied, 2)
}

func TestLoadPolicies_Good_EmptyPolicies(t *testing.T) {
	input := `{"policies": []}`
	policies, err := LoadPolicies(strings.NewReader(input))
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestLoadPolicies_Bad_InvalidJSON(t *testing.T) {
	_, err := LoadPolicies(strings.NewReader(`{invalid`))
	assert.Error(t, err)
}

func TestLoadPolicies_Bad_InvalidTier(t *testing.T) {
	input := `{"policies": [{"tier": 0, "allowed": ["repo.push"]}]}`
	_, err := LoadPolicies(strings.NewReader(input))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tier")
}

func TestLoadPolicies_Bad_TierTooHigh(t *testing.T) {
	input := `{"policies": [{"tier": 99, "allowed": ["repo.push"]}]}`
	_, err := LoadPolicies(strings.NewReader(input))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tier")
}

func TestLoadPolicies_Bad_UnknownField(t *testing.T) {
	input := `{"policies": [{"tier": 1, "allowed": ["repo.push"], "bogus": true}]}`
	_, err := LoadPolicies(strings.NewReader(input))
	assert.Error(t, err, "DisallowUnknownFields should reject unknown fields")
}

// --- LoadPoliciesFromFile ---

func TestLoadPoliciesFromFile_Good(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")
	err := os.WriteFile(path, []byte(validPolicyJSON), 0644)
	require.NoError(t, err)

	policies, err := LoadPoliciesFromFile(path)
	require.NoError(t, err)
	assert.Len(t, policies, 3)
}

func TestLoadPoliciesFromFile_Bad_NotFound(t *testing.T) {
	_, err := LoadPoliciesFromFile("/nonexistent/path/policies.json")
	assert.Error(t, err)
}

// --- ApplyPolicies ---

func TestApplyPolicies_Good(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{Name: "TestAgent", Tier: TierVerified}))
	pe := NewPolicyEngine(r)

	// Apply custom policies from JSON
	err := pe.ApplyPolicies(strings.NewReader(validPolicyJSON))
	require.NoError(t, err)

	// Verify the Tier 2 policy was replaced
	p := pe.GetPolicy(TierVerified)
	require.NotNil(t, p)
	assert.Len(t, p.Allowed, 2)
	assert.Contains(t, p.Allowed, CapCreatePR)
	assert.Contains(t, p.Allowed, CapCreateIssue)

	// Verify evaluation uses the new policy
	result := pe.Evaluate("TestAgent", CapPushRepo, "")
	assert.Equal(t, Deny, result.Decision, "repo.push should not be allowed under new Tier 2 policy")

	result = pe.Evaluate("TestAgent", CapCreatePR, "")
	assert.Equal(t, Allow, result.Decision)
}

func TestApplyPolicies_Bad_InvalidJSON(t *testing.T) {
	r := NewRegistry()
	pe := NewPolicyEngine(r)

	err := pe.ApplyPolicies(strings.NewReader(`{invalid`))
	assert.Error(t, err)
}

func TestApplyPolicies_Bad_InvalidTier(t *testing.T) {
	r := NewRegistry()
	pe := NewPolicyEngine(r)

	input := `{"policies": [{"tier": 0, "allowed": ["repo.push"]}]}`
	err := pe.ApplyPolicies(strings.NewReader(input))
	assert.Error(t, err)
}

// --- ApplyPoliciesFromFile ---

func TestApplyPoliciesFromFile_Good(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policies.json")
	err := os.WriteFile(path, []byte(validPolicyJSON), 0644)
	require.NoError(t, err)

	r := NewRegistry()
	require.NoError(t, r.Register(Agent{Name: "A", Tier: TierFull}))
	pe := NewPolicyEngine(r)

	err = pe.ApplyPoliciesFromFile(path)
	require.NoError(t, err)

	// Verify Tier 3 was replaced — only 3 allowed caps now
	p := pe.GetPolicy(TierFull)
	require.NotNil(t, p)
	assert.Len(t, p.Allowed, 3)
}

func TestApplyPoliciesFromFile_Bad_NotFound(t *testing.T) {
	r := NewRegistry()
	pe := NewPolicyEngine(r)
	err := pe.ApplyPoliciesFromFile("/nonexistent/policies.json")
	assert.Error(t, err)
}

// --- ExportPolicies ---

func TestExportPolicies_Good(t *testing.T) {
	r := NewRegistry()
	pe := NewPolicyEngine(r) // loads defaults

	var buf bytes.Buffer
	err := pe.ExportPolicies(&buf)
	require.NoError(t, err)

	// Output should be valid JSON
	var cfg PoliciesConfig
	err = json.Unmarshal(buf.Bytes(), &cfg)
	require.NoError(t, err)
	assert.Len(t, cfg.Policies, 3)
}

func TestExportPolicies_Good_RoundTrip(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{Name: "A", Tier: TierFull}))
	pe := NewPolicyEngine(r)

	// Export
	var buf bytes.Buffer
	err := pe.ExportPolicies(&buf)
	require.NoError(t, err)

	// Create a new engine and apply the exported policies
	r2 := NewRegistry()
	require.NoError(t, r2.Register(Agent{Name: "A", Tier: TierFull}))
	pe2 := NewPolicyEngine(r2)
	err = pe2.ApplyPolicies(strings.NewReader(buf.String()))
	require.NoError(t, err)

	// Evaluations should produce the same results
	caps := []Capability{CapPushRepo, CapMergePR, CapCreatePR, CapRunPrivileged}
	for _, cap := range caps {
		r1 := pe.Evaluate("A", cap, "")
		r2 := pe2.Evaluate("A", cap, "")
		assert.Equal(t, r1.Decision, r2.Decision,
			"decision mismatch for %s: original=%s, round-tripped=%s", cap, r1.Decision, r2.Decision)
	}
}

// --- Helper conversion ---

func TestToCapabilities_Good(t *testing.T) {
	caps := toCapabilities([]string{"repo.push", "pr.merge"})
	assert.Len(t, caps, 2)
	assert.Equal(t, CapPushRepo, caps[0])
	assert.Equal(t, CapMergePR, caps[1])
}

func TestToCapabilities_Good_Empty(t *testing.T) {
	assert.Nil(t, toCapabilities(nil))
	assert.Nil(t, toCapabilities([]string{}))
}

func TestFromCapabilities_Good(t *testing.T) {
	ss := fromCapabilities([]Capability{CapPushRepo, CapMergePR})
	assert.Len(t, ss, 2)
	assert.Equal(t, "repo.push", ss[0])
	assert.Equal(t, "pr.merge", ss[1])
}

func TestFromCapabilities_Good_Empty(t *testing.T) {
	assert.Nil(t, fromCapabilities(nil))
	assert.Nil(t, fromCapabilities([]Capability{}))
}
