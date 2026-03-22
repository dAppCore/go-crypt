package trust

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	coreerr "dappco.re/go/core/log"
)

// PolicyConfig is the JSON-serialisable representation of a trust policy.
type PolicyConfig struct {
	Tier             int      `json:"tier"`
	Allowed          []string `json:"allowed"`
	RequiresApproval []string `json:"requires_approval,omitempty"`
	Denied           []string `json:"denied,omitempty"`
}

// PoliciesConfig is the top-level configuration containing all tier policies.
type PoliciesConfig struct {
	Policies []PolicyConfig `json:"policies"`
}

// LoadPoliciesFromFile reads a JSON file and returns parsed policies.
func LoadPoliciesFromFile(path string) ([]Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, coreerr.E("trust.LoadPoliciesFromFile", "failed to open file", err)
	}
	defer f.Close()
	return LoadPolicies(f)
}

// LoadPolicies reads JSON from a reader and returns parsed policies.
func LoadPolicies(r io.Reader) ([]Policy, error) {
	var cfg PoliciesConfig
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
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
			return nil, coreerr.E("trust.LoadPolicies", fmt.Sprintf("invalid tier %d at index %d", pc.Tier, i), nil)
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
func (pe *PolicyEngine) ApplyPoliciesFromFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return coreerr.E("trust.ApplyPoliciesFromFile", "failed to open file", err)
	}
	defer f.Close()
	return pe.ApplyPolicies(f)
}

// ExportPolicies serialises the current policies as JSON to the given writer.
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

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(cfg); err != nil {
		return coreerr.E("trust.ExportPolicies", "failed to encode JSON", err)
	}
	return nil
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
