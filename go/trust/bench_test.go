package trust

import (
	"testing"

	core "dappco.re/go"
)

// BenchmarkPolicyEvaluate measures policy evaluation across 100 registered agents.
func BenchmarkPolicyEvaluate(b *testing.B) {
	r := NewRegistry()
	for i := range 100 {
		tier := TierUntrusted
		switch i % 3 {
		case 0:
			tier = TierFull
		case 1:
			tier = TierVerified
		}
		_ = r.Register(Agent{
			Name:        core.Sprintf("agent-%d", i),
			Tier:        tier,
			ScopedRepos: []string{"host-uk/core", "host-uk/docs"},
		})
	}
	pe := NewPolicyEngine(r)

	caps := []Capability{
		CapPushRepo, CapCreatePR, CapMergePR, CapCommentIssue,
		CapCreateIssue, CapReadSecrets, CapRunPrivileged,
		CapAccessWorkspace, CapModifyFlows,
	}

	b.ResetTimer()
	for i := range b.N {
		agentName := core.Sprintf("agent-%d", i%100)
		cap := caps[i%len(caps)]
		_ = pe.Evaluate(agentName, cap, "host-uk/core")
	}
}

// BenchmarkRegistryGet measures agent lookup performance.
func BenchmarkRegistryGet(b *testing.B) {
	r := NewRegistry()
	for i := range 100 {
		_ = r.Register(Agent{
			Name: core.Sprintf("agent-%d", i),
			Tier: TierVerified,
		})
	}

	b.ResetTimer()
	for i := range b.N {
		name := core.Sprintf("agent-%d", i%100)
		_ = r.Get(name)
	}
}

// BenchmarkRegistryRegister measures agent registration performance.
func BenchmarkRegistryRegister(b *testing.B) {
	r := NewRegistry()

	b.ResetTimer()
	for i := range b.N {
		_ = r.Register(Agent{
			Name: core.Sprintf("bench-agent-%d", i),
			Tier: TierVerified,
		})
	}
}
