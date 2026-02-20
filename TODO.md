# TODO.md — go-crypt

Dispatched from core/go orchestration. Pick up tasks in order.

---

## Phase 0: Test Coverage & Hardening

- [ ] **Expand auth/ tests** — Add: concurrent session creation (10 goroutines), session token uniqueness (generate 1000, verify no collisions), challenge expiry edge case (5min boundary), empty password registration, very long username (10K chars), Unicode username/password, air-gapped round-trip (write challenge file → read response file), refresh already-expired session.
- [ ] **Expand crypt/ tests** — Add: wrong passphrase decrypt (should error, not corrupt), empty plaintext encrypt/decrypt round-trip, very large plaintext (10MB), key derivation determinism (same input → same output), HKDF with different info strings produce different keys, checksum of empty file, checksum of non-existent file (error handling).
- [ ] **Expand trust/ tests** — Add: concurrent Register/Get/Remove (race test), policy evaluation with empty ScopedRepos on Tier 2, capability not in any list (should deny), register agent with Tier 0 (invalid), rate limit enforcement verification, token expiry boundary tests.
- [ ] **Security audit** — Verify: constant-time comparisons used everywhere (not just HMAC), no timing side channels in session validation, nonce generation uses crypto/rand (not math/rand), PGP private keys zeroed after use, no secrets in error messages or logs.
- [ ] **`go vet ./...` clean** — Fix any warnings.
- [ ] **Benchmark suite** — `BenchmarkArgon2Derive` (KDF), `BenchmarkChaCha20` (encrypt 1KB/1MB), `BenchmarkRSAEncrypt` (2048/4096 bit), `BenchmarkPGPSign`, `BenchmarkPolicyEvaluate` (100 agents).

## Phase 1: Session Persistence

- [ ] **Session storage interface** — Extract in-memory session map into `SessionStore` interface with `Get`, `Set`, `Delete`, `Cleanup` methods.
- [ ] **SQLite session store** — Implement `SessionStore` backed by go-store (SQLite KV). Migrate session tokens + expiry to persistent storage.
- [ ] **Background cleanup** — Goroutine to purge expired sessions periodically. Configurable interval.
- [ ] **Session migration** — Backward-compatible: in-memory as default, optional persistent store via config.

## Phase 2: Key Management

- [ ] **Key rotation** — Add `RotateKeyPair(userID, oldPassword, newPassword)` to auth.Authenticator. Generate new keypair, re-encrypt metadata, update stored keys.
- [ ] **Key revocation** — Implement revocation certificate flow. Currently `.rev` is a placeholder.
- [ ] **Hardware key support** — Interface for PKCS#11 / YubiKey backing. Not implemented, but define the contract.

## Phase 3: Trust Policy Extensions

- [ ] **Approval workflow** — Implement the approval flow that `NeedsApproval` decisions point to. Queue-based: agent requests approval → admin reviews → approve/deny.
- [ ] **Audit log** — Record all policy evaluations (agent, capability, decision, timestamp). Append-only log for compliance.
- [ ] **Dynamic policies** — Load policies from YAML/JSON config. Currently hardcoded in `DefaultPolicies()`.
- [ ] **Scope wildcards** — Support `core/*` scope patterns in ScopedRepos, not just exact strings.

---

## Workflow

1. Virgil in core/go writes tasks here after research
2. This repo's dedicated session picks up tasks in phase order
3. Mark `[x]` when done, note commit hash
