# TODO.md — go-crypt

Dispatched from core/go orchestration. Pick up tasks in order.

---

## Phase 0: Test Coverage & Hardening

- [x] **Expand auth/ tests** — Added 8 new tests: concurrent session creation (10 goroutines), session token uniqueness (1000 tokens), challenge expiry boundary, empty password registration, very long username (10K chars), Unicode username/password, air-gapped round-trip, refresh already-expired session. All pass with `-race`.
- [x] **Expand crypt/ tests** — Added 12 new tests: wrong passphrase decrypt (ChaCha20+AES), empty plaintext round-trip (ChaCha20+AES), 1MB payload round-trip (ChaCha20+AES), ciphertext-too-short rejection, key derivation determinism (Argon2id+scrypt), HKDF different info strings, HKDF nil salt, checksum of empty file (SHA-256+SHA-512), checksum of non-existent file, checksum consistency with SHA256Sum. Note: large payload test uses 1MB (not 10MB) to keep tests fast.
- [x] **Expand trust/ tests** — Added 9 new tests: concurrent Register/Get/Remove (10 goroutines, race-safe), Tier 0 rejection, negative tier rejection, token expiry boundary, zero-value token expiry, concurrent List during mutations, empty ScopedRepos behaviour (documented as finding F3), capability not in any list, concurrent Evaluate.
- [x] **Security audit** — Full audit documented in FINDINGS.md. 4 findings: F1 (LTHN used for passwords, medium), F2 (PGP keys not zeroed, low), F3 (empty ScopedRepos bypasses scope, medium), F4 (go vet clean). No `math/rand` usage. All nonces use `crypto/rand`. No secrets in error messages.
- [x] **`go vet ./...` clean** — No warnings.
- [x] **Benchmark suite** — Created `crypt/bench_test.go` (7 benchmarks: Argon2Derive, ChaCha20 1KB/1MB, AESGCM 1KB/1MB, HMACSHA256 1KB, VerifyHMACSHA256) and `trust/bench_test.go` (3 benchmarks: PolicyEvaluate 100 agents, RegistryGet, RegistryRegister).

## Phase 1: Session Persistence

- [x] **Session storage interface** — Extracted in-memory session map into `SessionStore` interface with `Get`, `Set`, `Delete`, `DeleteByUser`, `Cleanup` methods. `MemorySessionStore` wraps the original map+mutex pattern. `ErrSessionNotFound` sentinel error.
- [x] **SQLite session store** — `SQLiteSessionStore` backed by go-store (SQLite KV). Sessions stored as JSON in `"sessions"` group. Mutex-serialised for SQLite single-writer safety.
- [x] **Background cleanup** — `StartCleanup(ctx, interval)` goroutine purges expired sessions periodically. Stops on context cancellation.
- [x] **Session migration** — Backward-compatible: `MemorySessionStore` is default, `WithSessionStore(store)` option for persistent store. All existing tests updated and passing. Commit `1aeabfd`.

## Phase 2: Key Management

### Step 2.1: Password hash migration (addresses Finding F1)

- [ ] **Migrate Login() from LTHN to Argon2id** — Currently `auth.Login()` verifies passwords via `lthn.Verify()` which uses non-constant-time comparison. Change to use `crypt.HashPassword()`/`crypt.VerifyPassword()` (Argon2id) for new registrations. Add migration path: on login, if stored hash is LTHN format, re-hash with Argon2id and update `.lthn` file. Update `.lthn` file extension to `.hash` or keep for backward compatibility.

### Step 2.2: Key rotation

- [ ] **Add `RotateKeyPair(userID, oldPassword, newPassword string) (*User, error)`** — Full flow:
  1. Load current `.key` and `.pub` via `io.Medium`
  2. Decrypt metadata `.json` with old private key + oldPassword via `pgp.Decrypt()`
  3. Generate new keypair via `pgp.CreateKeyPair(userID, userID+"@auth.local", newPassword)`
  4. Re-encrypt metadata with new public key via `pgp.Encrypt()`
  5. Write new `.key`, `.pub`, `.json` files (overwrite existing)
  6. Invalidate all sessions for this user via `store.DeleteByUser(userID)`
  7. Return updated User struct

- [ ] **Test RotateKeyPair** — Register user → rotate → verify old key can't decrypt → verify new key works → verify sessions invalidated.

### Step 2.3: Key revocation

- [ ] **Replace `.rev` placeholder** — Currently stores literal string `"REVOCATION_PLACEHOLDER"`. Options:
  - Option A: Generate proper OpenPGP revocation cert (may need go-crypto API research)
  - Option B: Store revocation timestamp + reason as JSON (simpler, sufficient for our use case)
  - Implement `RevokeKey(userID, password string) error` and `IsRevoked(userID string) bool`

### Step 2.4: Hardware key interface (contract only)

- [ ] **Define HardwareKey interface** — Contract for PKCS#11 / YubiKey integration:
  ```go
  type HardwareKey interface {
      Sign(data []byte) ([]byte, error)
      Decrypt(ciphertext []byte) ([]byte, error)
      GetPublicKey() (string, error)
      IsAvailable() bool
  }
  ```
  Add `WithHardwareKey(HardwareKey) Option` to Authenticator. No implementation yet — just the interface and integration points in auth.go.

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
