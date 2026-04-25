package trust

import (
<<<<<<< HEAD
=======
	"encoding/json"
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
	"io"

<<<<<<< HEAD
	core "dappco.re/go/core"
	coreerr "dappco.re/go/log"
=======
	"dappco.re/go/core"
	coreerr "dappco.re/go/log"
>>>>>>> 5927297 (fix(crypt): AX-6 banned-import purge across auth/cmd/crypt/trust (#414))
)

// PolicyConfig is the JSON-serialisable representation of a trust policy.
// Usage: use PolicyConfig with the other exported helpers in this package.
type PolicyConfig struct {
	Tier             int      `json:"tier"`
	Allowed          []string `json:"allowed"`
	RequiresApproval []string `json:"requires_approval,omitempty"`
	Denied           []string `json:"denied,omitempty"`
}

// PoliciesConfig is the top-level configuration containing all tier policies.
// Usage: use PoliciesConfig with the other exported helpers in this package.
type PoliciesConfig struct {
	Policies []PolicyConfig `json:"policies"`
}

// LoadPoliciesFromFile reads a JSON file and returns parsed policies.
// Usage: call LoadPoliciesFromFile(...) during the package's normal workflow.
func LoadPoliciesFromFile(path string) ([]Policy, error) {
	openResult := (&core.Fs{}).New("/").Open(path)
	if !openResult.OK {
		err, _ := openResult.Value.(error)
		return nil, coreerr.E("trust.LoadPoliciesFromFile", "failed to open file", err)
	}
	return LoadPolicies(openResult.Value.(io.Reader))
}

// LoadPolicies reads JSON from a reader and returns parsed policies.
// Usage: call LoadPolicies(...) during the package's normal workflow.
func LoadPolicies(r io.Reader) ([]Policy, error) {
	readResult := core.ReadAll(r)
	if !readResult.OK {
		err, _ := readResult.Value.(error)
		return nil, coreerr.E("trust.LoadPolicies", "failed to decode JSON", err)
	}

	data := []byte(readResult.Value.(string))
	if err := validatePoliciesJSON(data); err != nil {
		return nil, coreerr.E("trust.LoadPolicies", "failed to decode JSON", err)
	}

	var cfg PoliciesConfig
	decodeResult := core.JSONUnmarshal(data, &cfg)
	if !decodeResult.OK {
		err, _ := decodeResult.Value.(error)
		return nil, coreerr.E("trust.LoadPolicies", "failed to decode JSON", err)
	}
	return convertPolicies(cfg)
}

// convertPolicies transforms config DTOs into domain Policy structs.
func convertPolicies(cfg PoliciesConfig) ([]Policy, error) {
	var policies []Policy

	for i, pc := range cfg.Policies {
		tier := Tier(pc.Tier)
		if !tier.Valid() {
			return nil, coreerr.E("trust.LoadPolicies", core.Sprintf("invalid tier %d at index %d", pc.Tier, i), nil)
		}

		p := Policy{
			Tier:             tier,
			Allowed:          toCapabilities(pc.Allowed),
			RequiresApproval: toCapabilities(pc.RequiresApproval),
			Denied:           toCapabilities(pc.Denied),
		}
		policies = append(policies, p)
	}

	return policies, nil
}

// ApplyPolicies loads policies from a reader and sets them on the engine,
// replacing any existing policies for the same tiers.
// Usage: call ApplyPolicies(...) during the package's normal workflow.
func (pe *PolicyEngine) ApplyPolicies(r io.Reader) error {
	policies, err := LoadPolicies(r)
	if err != nil {
		return err
	}
	for _, p := range policies {
		if err := pe.SetPolicy(p); err != nil {
			return coreerr.E("trust.ApplyPolicies", "failed to set policy", err)
		}
	}
	return nil
}

// ApplyPoliciesFromFile loads policies from a JSON file and sets them on the engine.
// Usage: call ApplyPoliciesFromFile(...) during the package's normal workflow.
func (pe *PolicyEngine) ApplyPoliciesFromFile(path string) error {
	openResult := (&core.Fs{}).New("/").Open(path)
	if !openResult.OK {
		err, _ := openResult.Value.(error)
		return coreerr.E("trust.ApplyPoliciesFromFile", "failed to open file", err)
	}
	return pe.ApplyPolicies(openResult.Value.(io.Reader))
}

// ExportPolicies serialises the current policies as JSON to the given writer.
// Usage: call ExportPolicies(...) during the package's normal workflow.
func (pe *PolicyEngine) ExportPolicies(w io.Writer) error {
	var cfg PoliciesConfig
	for _, tier := range []Tier{TierUntrusted, TierVerified, TierFull} {
		p := pe.GetPolicy(tier)
		if p == nil {
			continue
		}
		cfg.Policies = append(cfg.Policies, PolicyConfig{
			Tier:             int(p.Tier),
			Allowed:          fromCapabilities(p.Allowed),
			RequiresApproval: fromCapabilities(p.RequiresApproval),
			Denied:           fromCapabilities(p.Denied),
		})
	}

	dataResult := core.JSONMarshal(cfg)
	if !dataResult.OK {
		err, _ := dataResult.Value.(error)
		return coreerr.E("trust.ExportPolicies", "failed to encode JSON", err)
	}
	if _, err := w.Write(dataResult.Value.([]byte)); err != nil {
		return coreerr.E("trust.ExportPolicies", "failed to encode JSON", err)
	}
	return nil
}

func validatePoliciesJSON(data []byte) error {
	var raw map[string]any

	result := core.JSONUnmarshal(data, &raw)
	if !result.OK {
		err, _ := result.Value.(error)
		return err
	}

	for key := range raw {
		if key != "policies" {
			return core.NewError(core.Sprintf("json: unknown field %q", key))
		}
	}

	rawPolicies, ok := raw["policies"]
	if !ok {
		return nil
	}

	policies, ok := rawPolicies.([]any)
	if !ok {
		return nil
	}

	for _, rawPolicy := range policies {
		fields, ok := rawPolicy.(map[string]any)
		if !ok {
			continue
		}
		for key := range fields {
			if !isKnownPolicyConfigKey(key) {
				return core.NewError(core.Sprintf("json: unknown field %q", key))
			}
		}
	}

	return nil
}

func isKnownPolicyConfigKey(key string) bool {
	switch key {
	case "tier", "allowed", "requires_approval", "denied":
		return true
	default:
		return false
	}
}

// toCapabilities converts string slices to Capability slices.
func toCapabilities(ss []string) []Capability {
	if len(ss) == 0 {
		return nil
	}
	caps := make([]Capability, len(ss))
	for i, s := range ss {
		caps[i] = Capability(s)
	}
	return caps
}

// fromCapabilities converts Capability slices to string slices.
func fromCapabilities(caps []Capability) []string {
	if len(caps) == 0 {
		return nil
	}
	ss := make([]string, len(caps))
	for i, c := range caps {
		ss[i] = string(c)
	}
	return ss
}
