# Project History — go-crypt

## Origin

go-crypt was extracted from `forge.lthn.ai/core/go` on 16 February 2026
(extraction commit `8498ecf`). The repository started with a single extraction
commit — no prior per-file history. The original implementation was ported from
`dAppServer`'s `mod-auth/lethean.service.ts` (TypeScript).

At extraction the module contained ~1,938 source LOC across 14 files and ~1,770
test LOC (47.7% test ratio). The `auth/` and `trust/` packages each had strong
test suites; `crypt/` sub-packages varied from well-tested (`chachapoly/`, `pgp/`)
to lightly covered (the top-level `crypt.go`).

---

## Phase 0: Test Coverage and Hardening

**Status**: Complete.

**auth/ additions**: 8 new tests covering concurrent session creation (10
goroutines), session token uniqueness (1,000 tokens), challenge expiry boundary,
empty password registration, very long username (10K characters), Unicode
username and password, air-gapped round-trip, and refresh of an already-expired
session. All pass under `-race`.

**crypt/ additions**: 12 new tests covering wrong passphrase decryption
(ChaCha20 and AES), empty plaintext round-trip, 1MB payload round-trip (not 10MB
— kept fast), ciphertext-too-short rejection, key derivation determinism
(Argon2id and scrypt), HKDF with different info strings, HKDF with nil salt,
checksum of empty file (SHA-256 and SHA-512), checksum of non-existent file, and
checksum consistency with `SHA256Sum`.

**trust/ additions**: 9 new tests covering concurrent Register/Get/Remove (10
goroutines), Tier 0 and negative tier rejection, token expiry boundary, zero-value
token expiry, concurrent List during mutations, empty ScopedRepos behaviour
(documented as Finding F3), capability not in any list, and concurrent Evaluate.

**Security audit**: Full review of all source files for cryptographic hygiene.
Findings documented below. `go vet ./...` produces no warnings.

**Benchmark suite**: `crypt/bench_test.go` (7 benchmarks: Argon2Derive,
ChaCha20 1KB, ChaCha20 1MB, AESGCM 1KB, AESGCM 1MB, HMACSHA256 1KB,
VerifyHMACSHA256) and `trust/bench_test.go` (3 benchmarks: PolicyEvaluate 100
agents, RegistryGet, RegistryRegister).

---

## Phase 1: Session Persistence

**Status**: Complete. Commit `1aeabfd`.

Extracted the in-memory session map into a `SessionStore` interface with `Get`,
`Set`, `Delete`, `DeleteByUser`, and `Cleanup` methods. `ErrSessionNotFound`
sentinel error added.

`MemorySessionStore` wraps the original map and mutex pattern.
`SQLiteSessionStore` is backed by go-store (SQLite KV). Sessions are stored as
JSON in a `"sessions"` group. A mutex serialises all operations for SQLite
single-writer safety.

Background cleanup via `StartCleanup(ctx, interval)` goroutine. Stops on context
cancellation. All existing tests updated and passing.

---

## Phase 2: Key Management

**Status**: Complete. Commit `301eac1`. 55 tests total, all pass under `-race`.

### Step 2.1: Password Hash Migration (resolves Finding F1)

`Register` now uses `crypt.HashPassword()` (Argon2id) and writes a `.hash` file.
`Login` detects the hash format: tries `.hash` (Argon2id) first, falls back to
`.lthn` (LTHN). A successful legacy login transparently re-hashes with Argon2id
and writes the `.hash` file (best-effort). A shared `verifyPassword()` helper
handles the dual-path logic and is used by both `Login` and `RevokeKey`.

The `verifyPassword` helper was extracted after `TestRevokeKey_Bad` failed: new
registrations do not write `.lthn` files, so the original fallback returned
`"user not found"` instead of `"invalid password"`.

### Step 2.2: Key Rotation

`RotateKeyPair(userID, oldPassword, newPassword)` implements full key rotation:
load private key → decrypt metadata with old password → generate new PGP keypair
→ re-encrypt metadata with new public key → overwrite `.pub`, `.key`, `.json`,
`.hash` → invalidate sessions via `store.DeleteByUser`. 4 tests.

### Step 2.3: Key Revocation

Chose JSON revocation record (Option B) over OpenPGP revocation certificate
(Option A). `Revocation{UserID, Reason, RevokedAt}` is written as JSON to `.rev`.
`IsRevoked()` parses JSON and ignores the legacy `"REVOCATION_PLACEHOLDER"` string.
Both `Login` and `CreateChallenge` reject revoked users. 6 tests including legacy
user revocation.

### Step 2.4: Hardware Key Interface

`hardware.go` defines the `HardwareKey` interface: `Sign`, `Decrypt`,
`GetPublicKey`, `IsAvailable`. Configured via `WithHardwareKey()` option.
Contract-only — no concrete implementations exist. Integration points documented
in `auth.go` comments but not wired.

---

## Phase 3: Trust Policy Extensions

**Status**: Complete.

### Approval Workflow

`ApprovalQueue` with `Submit`, `Approve`, `Deny`, `Get`, `Pending`, `Len` methods.
Thread-safe with unique monotonic IDs, status tracking, reviewer attribution, and
timestamps. 22 tests including concurrent and end-to-end integration with
`PolicyEngine`.

### Audit Log

`AuditLog` with append-only `Record`, `Entries`, `EntriesFor`, `Len` methods.
Optional `io.Writer` for JSON-line persistence. Custom `Decision`
`MarshalJSON`/`UnmarshalJSON`. 18 tests including writer errors and concurrent
logging.

### Dynamic Policies

`LoadPolicies`/`LoadPoliciesFromFile` parse JSON config.
`ApplyPolicies`/`ApplyPoliciesFromFile` replace engine policies.
`ExportPolicies` for round-trip serialisation. `DisallowUnknownFields` for strict
parsing. 18 tests including round-trip.

### Scope Wildcards

`matchScope` supports exact match, single-level wildcard (`core/*`), and
recursive wildcard (`core/**`). `repoAllowed` updated to use pattern matching.
18 tests covering all edge cases including integration with `PolicyEngine`.

---

## Security Audit Findings

Conducted 2026-02-20. Full audit reviewed all source files for cryptographic hygiene.

### Finding F1: LTHN Hash Used for Password Verification (Medium) — RESOLVED

`auth.Login()` originally verified passwords via `lthn.Verify()`, which uses the
LTHN quasi-salted hash (RFC-0004) with a non-constant-time string comparison.
LTHN was designed for content identifiers, not passwords, and provides no random
salt. Resolved in Phase 2 (commit `301eac1`) by migrating to Argon2id with
transparent legacy path migration.

### Finding F2: PGP Private Keys Not Zeroed After Use (Low) — Open

In `pgp.Decrypt()` and `pgp.Sign()`, the private key is decrypted into memory
via `entity.PrivateKey.Decrypt()` but the decrypted key material is not zeroed
before garbage collection. The ProtonMail `go-crypto` library does not expose a
`Wipe()` or `Zero()` method on `packet.PrivateKey`. Resolving this would require
forking or patching the upstream library.

Severity is low: an attacker with read access to process memory already has full
access to the process. The Go runtime does not guarantee memory zeroing and
GC-managed runtimes inherently have this limitation.

### Finding F3: Empty ScopedRepos Bypasses Scope Check on Tier 2 (Medium) — Open

In `policy.go`, the repo scope check is conditioned on `len(agent.ScopedRepos) > 0`.
A Tier 2 agent with empty `ScopedRepos` (nil or `[]string{}`) is treated as
unrestricted rather than as having no access. If an admin registers a Tier 2
agent without explicitly setting `ScopedRepos`, it gets access to all repositories
for repo-scoped capabilities (`repo.push`, `pr.create`, `pr.merge`, `secrets.read`).

Potential remediation: treat empty `ScopedRepos` as no access for Tier 2 agents,
requiring explicit `["*"]` or `["org/**"]` for unrestricted access. This is a
design decision with backward-compatibility implications.

### Finding F4: `go vet` Clean — Passed

`go vet ./...` produces no warnings. All nonces use `crypto/rand`. No usage of
`math/rand` detected. No secrets in error messages.

---

## Known Limitations

### Dual ChaCha20 Implementations

`crypt/symmetric.go` and `crypt/chachapoly/chachapoly.go` implement nearly
identical ChaCha20-Poly1305 AEAD. The `chachapoly` sub-package pre-allocates
capacity before appending, which is a minor optimisation for small payloads. The
two packages have different import paths and test suites. Consolidation would
reduce duplication but would require updating all importers.

### LTHN Hash Non-Constant-Time Comparison

`lthn.Verify()` uses direct string comparison (`==`), not
`subtle.ConstantTimeCompare`. This is acceptable because LTHN is for content
identifiers where timing attacks are not a realistic threat model. However, the
package comment and doc string document this explicitly to prevent misuse.

### Policy Engine Does Not Enforce Workflow

`PolicyEngine.Evaluate()` returns `NeedsApproval` as a decision value but
provides no enforcement. The caller is responsible for submitting to the
`ApprovalQueue` and polling for resolution. A higher-level package (go-agentic
or go-scm) must implement the actual enforcement layer.

### Hardware Key Interface Is Contract-Only

The `HardwareKey` interface in `auth/hardware.go` has no concrete implementations.
PKCS#11, YubiKey, and TPM backends are planned but not implemented. The
`Authenticator.hardwareKey` field is never consulted in the current code.

### Session Cleanup Prints to Stdout

`StartCleanup` logs via `fmt.Printf` rather than a structured logger. This is
acceptable for a library that does not want to impose a logging dependency, but
callers that need structured logs should wrap or replace the cleanup goroutine.

---

## Future Considerations

- **Consolidate ChaCha20 wrappers**: merge `crypt/symmetric.go` and
  `crypt/chachapoly` into a single implementation.
- **Hardware key backends**: implement `HardwareKey` for PKCS#11 (via
  `miekg/pkcs11` or `ThalesIgnite/crypto11`) and YubiKey (via `go-piv`).
- **Resolve Finding F3**: require explicit wildcard for unrestricted Tier 2
  access; treat empty `ScopedRepos` as no-access.
- **Structured logging**: replace `fmt.Printf` in `StartCleanup` with an
  `slog.Logger` option on `Authenticator`.
- **Rate limiting enforcement**: the `Agent.RateLimit` field is stored in the
  registry but never enforced. An enforcement layer (middleware, interceptor)
  is needed in the consuming service.
- **Policy persistence**: `PolicyEngine` policies are in-memory only. A storage
  backend (similar to `SQLiteSessionStore`) would allow runtime policy changes
  to survive restarts.
