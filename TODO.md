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

- [x] **Migrate Login() from LTHN to Argon2id** — Register uses `crypt.HashPassword()` (Argon2id), writes `.hash` file. Login detects format: tries `.hash` (Argon2id) first, falls back to `.lthn` (LTHN). Successful legacy login transparently re-hashes with Argon2id. Shared `verifyPassword()` helper handles dual-path logic. 5 tests: RegisterArgon2id_Good, LoginArgon2id_Good, LoginArgon2id_Bad, LegacyLTHNMigration_Good, LegacyLTHNLogin_Bad.

### Step 2.2: Key rotation

- [x] **RotateKeyPair** — Full flow: load private key → decrypt metadata with old password → generate new PGP keypair → re-encrypt metadata → update .pub/.key/.json/.hash → invalidate sessions. 4 tests: RotateKeyPair_Good, RotateKeyPair_Bad (wrong password), RotateKeyPair_Ugly (non-existent user), RotateKeyPair_OldKeyCannotDecrypt_Good.

### Step 2.3: Key revocation

- [x] **RevokeKey + IsRevoked** — Option B chosen: JSON `Revocation{UserID, Reason, RevokedAt}` record in `.rev` file. `IsRevoked()` parses JSON, ignores legacy `"REVOCATION_PLACEHOLDER"`. Login and CreateChallenge reject revoked users. 6 tests including legacy user revocation.

### Step 2.4: Hardware key interface (contract only)

- [x] **HardwareKey interface** — `hardware.go`: Sign, Decrypt, GetPublicKey, IsAvailable methods. `WithHardwareKey()` option on Authenticator. Contract-only, no concrete implementations yet. Integration points documented in auth.go.

All Phase 2: commit `301eac1`. 55 tests total, all pass with `-race`.

## Phase 3: Trust Policy Extensions

- [x] **Approval workflow** — `ApprovalQueue` with `Submit`, `Approve`, `Deny`, `Get`, `Pending` methods. Thread-safe queue with unique IDs, status tracking, reviewer attribution. 22 tests including concurrent and end-to-end integration with PolicyEngine.
- [x] **Audit log** — `AuditLog` with append-only `Record`, `Entries`, `EntriesFor` methods. Optional `io.Writer` for JSON-line persistence. Custom `Decision` JSON marshalling. 18 tests including writer errors and concurrent logging.
- [x] **Dynamic policies** — `LoadPolicies`/`LoadPoliciesFromFile` parse JSON config. `ApplyPolicies`/`ApplyPoliciesFromFile` replace engine policies. `ExportPolicies` for round-trip serialisation. `DisallowUnknownFields` for strict parsing. 18 tests including round-trip.
- [x] **Scope wildcards** — `matchScope` supports exact match, single-level wildcard (`core/*`), and recursive wildcard (`core/**`). Updated `repoAllowed` to use pattern matching. 18 tests covering all edge cases including integration with PolicyEngine.

---

## Workflow

1. Virgil in core/go writes tasks here after research
2. This repo's dedicated session picks up tasks in phase order
3. Mark `[x]` when done, note commit hash
