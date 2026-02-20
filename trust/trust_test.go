package trust

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Tier ---

func TestTierString_Good(t *testing.T) {
	assert.Equal(t, "untrusted", TierUntrusted.String())
	assert.Equal(t, "verified", TierVerified.String())
	assert.Equal(t, "full", TierFull.String())
}

func TestTierString_Bad_Unknown(t *testing.T) {
	assert.Contains(t, Tier(99).String(), "unknown")
}

func TestTierValid_Good(t *testing.T) {
	assert.True(t, TierUntrusted.Valid())
	assert.True(t, TierVerified.Valid())
	assert.True(t, TierFull.Valid())
}

func TestTierValid_Bad(t *testing.T) {
	assert.False(t, Tier(0).Valid())
	assert.False(t, Tier(4).Valid())
	assert.False(t, Tier(-1).Valid())
}

// --- Registry ---

func TestRegistryRegister_Good(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "Athena", Tier: TierFull})
	require.NoError(t, err)
	assert.Equal(t, 1, r.Len())
}

func TestRegistryRegister_Good_SetsDefaults(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "Athena", Tier: TierFull})
	require.NoError(t, err)

	a := r.Get("Athena")
	require.NotNil(t, a)
	assert.Equal(t, 0, a.RateLimit) // full trust = unlimited
	assert.False(t, a.CreatedAt.IsZero())
}

func TestRegistryRegister_Good_TierDefaults(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{Name: "A", Tier: TierUntrusted}))
	require.NoError(t, r.Register(Agent{Name: "B", Tier: TierVerified}))
	require.NoError(t, r.Register(Agent{Name: "C", Tier: TierFull}))

	assert.Equal(t, 10, r.Get("A").RateLimit)
	assert.Equal(t, 60, r.Get("B").RateLimit)
	assert.Equal(t, 0, r.Get("C").RateLimit)
}

func TestRegistryRegister_Good_PreservesExplicitRateLimit(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "Custom", Tier: TierVerified, RateLimit: 30})
	require.NoError(t, err)
	assert.Equal(t, 30, r.Get("Custom").RateLimit)
}

func TestRegistryRegister_Good_Update(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{Name: "Athena", Tier: TierVerified}))
	require.NoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))

	assert.Equal(t, 1, r.Len())
	assert.Equal(t, TierFull, r.Get("Athena").Tier)
}

func TestRegistryRegister_Bad_EmptyName(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Tier: TierFull})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}

func TestRegistryRegister_Bad_InvalidTier(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "Bad", Tier: Tier(0)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tier")
}

func TestRegistryGet_Good(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	a := r.Get("Athena")
	require.NotNil(t, a)
	assert.Equal(t, "Athena", a.Name)
}

func TestRegistryGet_Bad_NotFound(t *testing.T) {
	r := NewRegistry()
	assert.Nil(t, r.Get("nonexistent"))
}

func TestRegistryRemove_Good(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	assert.True(t, r.Remove("Athena"))
	assert.Equal(t, 0, r.Len())
}

func TestRegistryRemove_Bad_NotFound(t *testing.T) {
	r := NewRegistry()
	assert.False(t, r.Remove("nonexistent"))
}

func TestRegistryList_Good(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	require.NoError(t, r.Register(Agent{Name: "Clotho", Tier: TierVerified}))

	agents := r.List()
	assert.Len(t, agents, 2)

	names := make(map[string]bool)
	for _, a := range agents {
		names[a.Name] = true
	}
	assert.True(t, names["Athena"])
	assert.True(t, names["Clotho"])
}

func TestRegistryList_Good_Empty(t *testing.T) {
	r := NewRegistry()
	assert.Empty(t, r.List())
}

func TestRegistryList_Good_Snapshot(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(Agent{Name: "Athena", Tier: TierFull}))
	agents := r.List()

	// Modifying the returned slice should not affect the registry.
	agents[0].Tier = TierUntrusted
	assert.Equal(t, TierFull, r.Get("Athena").Tier)
}

// --- Agent ---

func TestAgentTokenExpiry(t *testing.T) {
	agent := Agent{
		Name:           "Test",
		Tier:           TierVerified,
		TokenExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	assert.True(t, time.Now().After(agent.TokenExpiresAt))

	agent.TokenExpiresAt = time.Now().Add(1 * time.Hour)
	assert.True(t, time.Now().Before(agent.TokenExpiresAt))
}

// --- Phase 0 Additions ---

// TestConcurrentRegistryOperations_Good verifies that Register/Get/Remove
// from 10 goroutines do not race.
func TestConcurrentRegistryOperations_Good(t *testing.T) {
	r := NewRegistry()

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n * 3) // register + get + remove goroutines

	// Register goroutines
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("agent-%d", idx)
			err := r.Register(Agent{Name: name, Tier: TierVerified})
			assert.NoError(t, err)
		}(i)
	}

	// Get goroutines (may return nil if not yet registered)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("agent-%d", idx)
			_ = r.Get(name) // Just exercise the read path
		}(i)
	}

	// Remove goroutines (may return false if not yet registered or already removed)
	for i := 0; i < n; i++ {
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("agent-%d", idx)
			_ = r.Remove(name)
		}(i)
	}

	wg.Wait()
	// No panic or data race = success (run with -race flag)
}

// TestRegisterTierZero_Bad verifies that Tier 0 is rejected.
func TestRegisterTierZero_Bad(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "InvalidTierAgent", Tier: Tier(0)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tier")
}

// TestRegisterNegativeTier_Bad verifies that negative tiers are rejected.
func TestRegisterNegativeTier_Bad(t *testing.T) {
	r := NewRegistry()
	err := r.Register(Agent{Name: "NegativeTier", Tier: Tier(-1)})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid tier")
}

// TestTokenExpiryBoundary_Good verifies token expiry checking.
func TestTokenExpiryBoundary_Good(t *testing.T) {
	// Token that expires in the future — should be valid
	futureAgent := Agent{
		Name:           "FutureAgent",
		Tier:           TierVerified,
		TokenExpiresAt: time.Now().Add(1 * time.Millisecond),
	}
	assert.True(t, time.Now().Before(futureAgent.TokenExpiresAt))

	// Wait for it to expire
	time.Sleep(5 * time.Millisecond)
	assert.True(t, time.Now().After(futureAgent.TokenExpiresAt),
		"token should now be expired")
}

// TestTokenExpiryZeroValue_Ugly verifies zero-value TokenExpiresAt behaviour.
func TestTokenExpiryZeroValue_Ugly(t *testing.T) {
	agent := Agent{
		Name: "ZeroExpiry",
		Tier: TierVerified,
		// TokenExpiresAt is zero value
	}
	r := NewRegistry()
	err := r.Register(agent)
	require.NoError(t, err)

	// Zero-value time is in the past
	retrieved := r.Get("ZeroExpiry")
	require.NotNil(t, retrieved)
	assert.True(t, time.Now().After(retrieved.TokenExpiresAt),
		"zero-value token expiry should be in the past")
}

// TestConcurrentListDuringMutations_Good verifies List is safe during writes.
func TestConcurrentListDuringMutations_Good(t *testing.T) {
	r := NewRegistry()

	// Pre-populate
	for i := 0; i < 5; i++ {
		require.NoError(t, r.Register(Agent{
			Name: fmt.Sprintf("base-%d", i),
			Tier: TierFull,
		}))
	}

	var wg sync.WaitGroup
	wg.Add(20)

	// 10 goroutines listing
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			agents := r.List()
			_ = len(agents) // Use the result
		}()
	}

	// 10 goroutines mutating
	for i := 0; i < 10; i++ {
		go func(idx int) {
			defer wg.Done()
			name := fmt.Sprintf("concurrent-%d", idx)
			_ = r.Register(Agent{Name: name, Tier: TierUntrusted})
		}(i)
	}

	wg.Wait()
}
