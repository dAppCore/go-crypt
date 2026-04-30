package trust

import (
	"testing"

	core "dappco.re/go"
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

func TestConfig_LoadPolicies_Good(t *testing.T) {
	policies, err := LoadPolicies(core.NewReader(validPolicyJSON))
	mustNoError(t, err)
	wantLen(t, policies, 3)
}

func TestConfig_LoadPolicies_Good_FieldMapping(t *testing.T) {
	policies, err := LoadPolicies(core.NewReader(validPolicyJSON))
	mustNoError(t, err)

	// Tier 3
	wantEqual(t, TierFull, policies[0].Tier)
	wantLen(t, policies[0].Allowed, 3)
	wantContains(t, policies[0].Allowed, CapPushRepo)
	wantNil(t, policies[0].RequiresApproval)
	wantNil(t, policies[0].Denied)

	// Tier 2
	wantEqual(t, TierVerified, policies[1].Tier)
	wantLen(t, policies[1].Allowed, 2)
	wantLen(t, policies[1].RequiresApproval, 1)
	wantEqual(t, CapMergePR, policies[1].RequiresApproval[0])
	wantLen(t, policies[1].Denied, 1)

	// Tier 1
	wantEqual(t, TierUntrusted, policies[2].Tier)
	wantLen(t, policies[2].Allowed, 1)
	wantLen(t, policies[2].Denied, 2)
}

func TestConfig_LoadPolicies_Good_EmptyPolicies(t *testing.T) {
	input := `{"policies": []}`
	policies, err := LoadPolicies(core.NewReader(input))
	mustNoError(t, err)
	wantEmpty(t, policies)
}

func TestConfig_LoadPolicies_Bad_InvalidJSON(t *testing.T) {
	_, err := LoadPolicies(core.NewReader(`{invalid`))
	wantError(t, err)
}

func TestConfig_LoadPolicies_Bad_InvalidTier(t *testing.T) {
	input := `{"policies": [{"tier": 0, "allowed": ["repo.push"]}]}`
	_, err := LoadPolicies(core.NewReader(input))
	wantError(t, err)
	wantContains(t, err.Error(), "invalid tier")
}

func TestConfig_LoadPolicies_Bad_TierTooHigh(t *testing.T) {
	input := `{"policies": [{"tier": 99, "allowed": ["repo.push"]}]}`
	_, err := LoadPolicies(core.NewReader(input))
	wantError(t, err)
	wantContains(t, err.Error(), "invalid tier")
}

func TestConfig_LoadPolicies_Bad_UnknownField(t *testing.T) {
	input := `{"policies": [{"tier": 1, "allowed": ["repo.push"], "bogus": true}]}`
	_, err := LoadPolicies(core.NewReader(input))
	wantError(t, err, "DisallowUnknownFields should reject unknown fields")
}

// --- LoadPoliciesFromFile ---

func TestConfig_LoadPoliciesFromFile_Good(t *testing.T) {
	dir := t.TempDir()
	path := core.Path(dir, "policies.json")
	writePolicyFile(t, path, validPolicyJSON)

	policies, err := LoadPoliciesFromFile(path)
	mustNoError(t, err)
	wantLen(t, policies, 3)
}

func TestConfig_LoadPoliciesFromFile_Bad_NotFound(t *testing.T) {
	policies, err := LoadPoliciesFromFile("/nonexistent/path/policies.json")
	wantError(t, err)
	wantNil(t, policies)
}

// --- ApplyPolicies ---

func TestConfig_PolicyEngine_ApplyPolicies_Good(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{Name: "TestAgent", Tier: TierVerified}))
	pe := NewPolicyEngine(r)

	// Apply custom policies from JSON
	err := pe.ApplyPolicies(core.NewReader(validPolicyJSON))
	mustNoError(t, err)

	// Verify the Tier 2 policy was replaced
	p := pe.GetPolicy(TierVerified)
	mustNotNil(t, p)
	wantLen(t, p.Allowed, 2)
	wantContains(t, p.Allowed, CapCreatePR)
	wantContains(t, p.Allowed, CapCreateIssue)

	// Verify evaluation uses the new policy
	result := pe.Evaluate("TestAgent", CapPushRepo, "")
	wantEqual(t, Deny, result.Decision, "repo.push should not be allowed under new Tier 2 policy")

	result = pe.Evaluate("TestAgent", CapCreatePR, "")
	wantEqual(t, Allow, result.Decision)
}

func TestConfig_PolicyEngine_ApplyPolicies_Bad_InvalidJSON(t *testing.T) {
	r := NewRegistry()
	pe := NewPolicyEngine(r)

	err := pe.ApplyPolicies(core.NewReader(`{invalid`))
	wantError(t, err)
}

func TestConfig_PolicyEngine_ApplyPolicies_Bad_InvalidTier(t *testing.T) {
	r := NewRegistry()
	pe := NewPolicyEngine(r)

	input := `{"policies": [{"tier": 0, "allowed": ["repo.push"]}]}`
	err := pe.ApplyPolicies(core.NewReader(input))
	wantError(t, err)
}

// --- ApplyPoliciesFromFile ---

func TestConfig_PolicyEngine_ApplyPoliciesFromFile_Good(t *testing.T) {
	dir := t.TempDir()
	path := core.Path(dir, "policies.json")
	writePolicyFile(t, path, validPolicyJSON)

	r := NewRegistry()
	mustNoError(t, r.Register(Agent{Name: "A", Tier: TierFull}))
	pe := NewPolicyEngine(r)

	err := pe.ApplyPoliciesFromFile(path)
	mustNoError(t, err)

	// Verify Tier 3 was replaced — only 3 allowed caps now
	p := pe.GetPolicy(TierFull)
	mustNotNil(t, p)
	wantLen(t, p.Allowed, 3)
}

func TestConfig_PolicyEngine_ApplyPoliciesFromFile_Bad_NotFound(t *testing.T) {
	r := NewRegistry()
	pe := NewPolicyEngine(r)
	err := pe.ApplyPoliciesFromFile("/nonexistent/policies.json")
	wantError(t, err)
}

// --- ExportPolicies ---

func TestConfig_PolicyEngine_ExportPolicies_Good(t *testing.T) {
	r := NewRegistry()
	pe := NewPolicyEngine(r) // loads defaults

	buf := core.NewBuilder()
	err := pe.ExportPolicies(buf)
	mustNoError(t, err)

	// Output should be valid JSON
	var cfg PoliciesConfig
	result := core.JSONUnmarshalString(buf.String(), &cfg)
	mustTrue(t, result.OK, testMessagef("failed to unmarshal exported policies: %v", result.Value))
	wantLen(t, cfg.Policies, 3)
}

func TestConfig_PolicyEngine_ExportPolicies_Good_RoundTrip(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{Name: "A", Tier: TierFull}))
	pe := NewPolicyEngine(r)

	// Export
	buf := core.NewBuilder()
	err := pe.ExportPolicies(buf)
	mustNoError(t, err)

	// Create a new engine and apply the exported policies
	r2 := NewRegistry()
	mustNoError(t, r2.Register(Agent{Name: "A", Tier: TierFull}))
	pe2 := NewPolicyEngine(r2)
	err = pe2.ApplyPolicies(core.NewReader(buf.String()))
	mustNoError(t, err)

	// Evaluations should produce the same results
	caps := []Capability{CapPushRepo, CapMergePR, CapCreatePR, CapRunPrivileged}
	for _, cap := range caps {
		r1 := pe.Evaluate("A", cap, "")
		r2 := pe2.Evaluate("A", cap, "")
		wantEqual(t, r1.Decision, r2.Decision,
			testMessagef("decision mismatch for %s: original=%s, round-tripped=%s", cap, r1.Decision, r2.Decision))
	}
}

func writePolicyFile(t *testing.T, path, content string) {
	t.Helper()

	result := (&core.Fs{}).New("/").WriteMode(path, content, 0o644)
	mustTrue(t, result.OK, testMessagef("failed to write %s: %v", path, result.Value))
}

// --- Helper conversion ---

func TestConfig_ToCapabilities_Good(t *testing.T) {
	caps := toCapabilities([]string{"repo.push", "pr.merge"})
	wantLen(t, caps, 2)
	wantEqual(t, CapPushRepo, caps[0])
	wantEqual(t, CapMergePR, caps[1])
}

func TestConfig_ToCapabilities_Good_Empty(t *testing.T) {
	nilCaps := toCapabilities(nil)
	emptyCaps := toCapabilities([]string{})
	wantNil(t, nilCaps)
	wantNil(t, emptyCaps)
}

func TestConfig_FromCapabilities_Good(t *testing.T) {
	ss := fromCapabilities([]Capability{CapPushRepo, CapMergePR})
	wantLen(t, ss, 2)
	wantEqual(t, "repo.push", ss[0])
	wantEqual(t, "pr.merge", ss[1])
}

func TestConfig_FromCapabilities_Good_Empty(t *testing.T) {
	nilStrings := fromCapabilities(nil)
	emptyStrings := fromCapabilities([]Capability{})
	wantNil(t, nilStrings)
	wantNil(t, emptyStrings)
}
