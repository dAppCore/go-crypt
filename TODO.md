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
