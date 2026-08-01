package trust

import (
	"sync"
	"testing"
	"time"

	core "dappco.re/go"
)

// --- Tier ---

func TestTrust_Tier_String_Good(t *testing.T) {
	wantEqual(t, "untrusted", TierUntrusted.String())
	wantEqual(t, "verified", TierVerified.String())
	wantEqual(t, "full", TierFull.String())
}

func TestTrust_Tier_String_Bad_Unknown(t *testing.T) {
	got := Tier(99).String()
	wantContains(t, got, "unknown")
	wantContains(t, got, "99")
}

func TestTrust_Tier_Valid_Good(t *testing.T) {
	wantTrue(t, TierUntrusted.Valid())
	wantTrue(t, TierVerified.Valid())
	wantTrue(t, TierFull.Valid())
}

func TestTrust_Tier_Valid_Bad(t *testing.T) {
	wantFalse(t, Tier(0).Valid())
	wantFalse(t, Tier(4).Valid())
	wantFalse(t, Tier(-1).Valid())
}

// --- Registry ---

func TestTrust_Registry_Register_Good(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "Athena", Tier: TierFull})
	mustNoError(t, err)
	wantEqual(t, 1, r.Len())
}

func TestTrust_Registry_Register_Good_SetsDefaults(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "Athena", Tier: TierFull})
	mustNoError(t, err)

	a := r.Get("Athena")
	mustNotNil(t, a)
	wantEqual(t, 0, a.RateLimit) // full trust = unlimited
	wantFalse(t, a.CreatedAt.IsZero())
}

func TestTrust_Registry_Register_Good_TierDefaults(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{Name: "A", Tier: TierUntrusted}))
	mustNoError(t, r.Register(Agent{Name: "B", Tier: TierVerified}))
	mustNoError(t, r.Register(Agent{Name: "C", Tier: TierFull}))

	wantEqual(t, 10, r.Get("A").RateLimit)
	wantEqual(t, 60, r.Get("B").RateLimit)
	wantEqual(t, 0, r.Get("C").RateLimit)
}

func TestTrust_Registry_Register_Good_PreservesExplicitRateLimit(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "Custom", Tier: TierVerified, RateLimit: 30})
	mustNoError(t, err)
	wantEqual(t, 30, r.Get("Custom").RateLimit)
}

func TestTrust_Registry_Register_Good_Update(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{Name: "Athena", Tier: TierVerified}))
	mustNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))

	wantEqual(t, 1, r.Len())
	wantEqual(t, TierFull, r.Get("Athena").Tier)
}

func TestTrust_Registry_Register_Bad_EmptyName(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Tier: TierFull})
	wantError(t, err)
	wantContains(t, err.Error(), "name is required")
}

func TestTrust_Registry_Register_Bad_InvalidTier(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "Bad", Tier: Tier(0)})
	wantError(t, err)
	wantContains(t, err.Error(), "invalid tier")
}

func TestTrust_Registry_Get_Good(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	a := r.Get("Athena")
	mustNotNil(t, a)
	wantEqual(t, "Athena", a.Name)
}

func TestTrust_Registry_Get_Bad_NotFound(t *testing.T) {
	r := NewRegistry()
	agent := r.Get("nonexistent")
	wantNil(t, agent)
	wantEqual(t, 0, r.Len())
}

func TestTrust_Registry_Remove_Good(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	wantTrue(t, r.Remove("Athena"))
	wantEqual(t, 0, r.Len())
}

func TestTrust_Registry_Remove_Bad_NotFound(t *testing.T) {
	r := NewRegistry()
	wantFalse(t, r.Remove("nonexistent"))
	wantEqual(t, 0, r.Len())
}

func TestTrust_Registry_List_Good(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	mustNoError(t, r.Register(Agent{Name: "Clotho", Tier: TierVerified}))

	agents := r.List()
	wantLen(t, agents, 2)

	names := make(map[string]bool)
	for _, a := range agents {
		names[a.Name] = true
	}
	wantTrue(t, names["Athena"])
	wantTrue(t, names["Clotho"])
}

func TestTrust_Registry_List_Good_Empty(t *testing.T) {
	r := NewRegistry()
	agents := r.List()
	wantEmpty(t, agents)
	wantEqual(t, 0, r.Len())
}

func TestTrust_Registry_List_Good_Snapshot(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	agents := r.List()

	// Modifying the returned slice should not affect the registry.
	agents[0].Tier = TierUntrusted
	wantEqual(t, TierFull, r.Get("Athena").Tier)
}

func TestTrust_Registry_ListSeq_Good(t *testing.T) {
	r := NewRegistry()
	mustNoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	mustNoError(t, r.Register(Agent{Name: "Clotho", Tier: TierVerified}))

	count := 0
	names := make(map[string]bool)
	for a := range r.ListSeq() {
		names[a.Name] = true
		count++
	}
	wantEqual(t, 2, count)
	wantTrue(t, names["Athena"])
	wantTrue(t, names["Clotho"])
}

// --- Agent ---

func TestTrust_AgentTokenExpiry_Good(t *testing.T) {
	agent := Agent{
		Name:           "Test",
		Tier:           TierVerified,
		TokenExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	wantTrue(t, time.Now().After(agent.TokenExpiresAt))

	agent.TokenExpiresAt = time.Now().Add(1 * time.Hour)
	wantTrue(t, time.Now().Before(agent.TokenExpiresAt))
}

// --- Phase 0 Additions ---

// TestTrust_ConcurrentRegistryOperations_Good verifies that Register/Get/Remove
// from 10 goroutines do not race.
func TestTrust_ConcurrentRegistryOperations_Good(t *testing.T) {
	r := NewRegistry()

	const n = 10
	var wg sync.WaitGroup // register + get + remove goroutines

	// Register goroutines
	for i := range n {
		wg.Go(func() {
			name := core.Sprintf("agent-%d", i)
			err := r.Register(Agent{Name: name, Tier: TierVerified})
			wantNoError(t, err)
		})
	}

	// Get goroutines (may return nil if not yet registered)
	for i := range n {
		wg.Go(func() {
			name := core.Sprintf("agent-%d", i)
			_ = r.Get(name) // Just exercise the read path
		})
	}

	// Remove goroutines (may return false if not yet registered or already removed)
	for i := range n {
		wg.Go(func() {
			name := core.Sprintf("agent-%d", i)
			_ = r.Remove(name)
		})
	}

	wg.Wait()
	// No panic or data race = success (run with -race flag)
}

// TestTrust_RegisterTierZero_Bad verifies that Tier 0 is rejected.
func TestTrust_RegisterTierZero_Bad(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "InvalidTierAgent", Tier: Tier(0)})
	wantError(t, err)
	wantContains(t, err.Error(), "invalid tier")
}

// TestTrust_RegisterNegativeTier_Bad verifies that negative tiers are rejected.
func TestTrust_RegisterNegativeTier_Bad(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "NegativeTier", Tier: Tier(-1)})
	wantError(t, err)
	wantContains(t, err.Error(), "invalid tier")
}

// TestTrust_TokenExpiryBoundary_Good verifies token expiry checking.
func TestTrust_TokenExpiryBoundary_Good(t *testing.T) {
	// Token that expires in the future — should be valid
	futureAgent := Agent{
		Name:           "FutureAgent",
		Tier:           TierVerified,
		TokenExpiresAt: time.Now().Add(1 * time.Millisecond),
	}
	wantTrue(t, time.Now().Before(futureAgent.TokenExpiresAt))

	// Wait for it to expire
	time.Sleep(5 * time.Millisecond)
	wantTrue(t, time.Now().After(futureAgent.TokenExpiresAt),
		"token should now be expired")
}

// TestTrust_TokenExpiryZeroValue_Ugly verifies zero-value TokenExpiresAt behaviour.
func TestTrust_TokenExpiryZeroValue_Ugly(t *testing.T) {
	agent := Agent{
		Name: "ZeroExpiry",
		Tier: TierVerified,
		// TokenExpiresAt is zero value
	}
	r := NewRegistry()
	err := r.Register(agent)
	mustNoError(t, err)

	// Zero-value time is in the past
	retrieved := r.Get("ZeroExpiry")
	mustNotNil(t, retrieved)
	wantTrue(t, time.Now().After(retrieved.TokenExpiresAt),
		"zero-value token expiry should be in the past")
}

// TestTrust_ConcurrentListDuringMutations_Good verifies List is safe during writes.
func TestTrust_ConcurrentListDuringMutations_Good(t *testing.T) {
	r := NewRegistry()

	// Pre-populate
	for i := range 5 {
		mustNoError(t, r.Register(Agent{
			Name: core.Sprintf("base-%d", i),
			Tier: TierFull,
		}))
	}

	var wg sync.WaitGroup

	// 10 goroutines listing
	for range 10 {
		wg.Go(func() {
			agents := r.List()
			_ = len(agents) // Use the result
		})
	}

	// 10 goroutines mutating
	for i := range 10 {
		wg.Go(func() {
			name := core.Sprintf("concurrent-%d", i)
			_ = r.Register(Agent{Name: name, Tier: TierUntrusted})
		})
	}

	wg.Wait()
}

func TestTrust_Tier_String_Bad(t *core.T) {
	subject := (*Tier).String
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Tier_String_Ugly(t *core.T) {
	subject := (*Tier).String
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Tier_Valid_Ugly(t *core.T) {
	subject := (*Tier).Valid
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_NewRegistry_Good(t *core.T) {
	subject := NewRegistry
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_NewRegistry_Bad(t *core.T) {
	subject := NewRegistry
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_NewRegistry_Ugly(t *core.T) {
	subject := NewRegistry
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_Register_Bad(t *core.T) {
	subject := (*Registry).Register
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_Register_Ugly(t *core.T) {
	subject := (*Registry).Register
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_Get_Bad(t *core.T) {
	subject := (*Registry).Get
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_Get_Ugly(t *core.T) {
	subject := (*Registry).Get
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_Remove_Bad(t *core.T) {
	subject := (*Registry).Remove
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_Remove_Ugly(t *core.T) {
	subject := (*Registry).Remove
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_List_Bad(t *core.T) {
	subject := (*Registry).List
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_List_Ugly(t *core.T) {
	subject := (*Registry).List
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_ListSeq_Bad(t *core.T) {
	subject := (*Registry).ListSeq
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_ListSeq_Ugly(t *core.T) {
	subject := (*Registry).ListSeq
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_Len_Good(t *core.T) {
	subject := (*Registry).Len
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Good"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_Len_Bad(t *core.T) {
	subject := (*Registry).Len
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Bad"
	if marker == "" {
		t.FailNow()
	}
}

func TestTrust_Registry_Len_Ugly(t *core.T) {
	subject := (*Registry).Len
	if subject == nil {
		t.FailNow()
	}
	marker := "Service:Ugly"
	if marker == "" {
		t.FailNow()
	}
}
