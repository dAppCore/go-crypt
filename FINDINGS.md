# FINDINGS.md — go-crypt Research & Discovery

## 2026-02-20: Initial Analysis (Virgil)

### Origin

Extracted from `core/go` on 16 Feb 2026 (commit `8498ecf`). Single extraction commit — fresh repo with no prior history.

### Package Inventory

| Package | Source LOC | Test LOC | Test Count | Notes |
|---------|-----------|----------|-----------|-------|
| `auth/` | 455 | 581 | 25+ | OpenPGP challenge-response + LTHN password |
| `crypt/` | 90 | 45 | 4 | High-level encrypt/decrypt convenience |
| `crypt/kdf.go` | 60 | 56 | — | Argon2id, scrypt, HKDF |
| `crypt/symmetric.go` | 100 | 55 | — | ChaCha20-Poly1305, AES-256-GCM |
| `crypt/hash.go` | 89 | 50 | — | Argon2id password hashing, Bcrypt |
| `crypt/hmac.go` | 30 | 40 | — | HMAC-SHA256/512 |
| `crypt/checksum.go` | 55 | 23 | — | SHA-256/512 file and data checksums |
| `crypt/chachapoly/` | 50 | 114 | 9 | Standalone ChaCha20-Poly1305 wrapper |
| `crypt/lthn/` | 94 | 66 | 6 | RFC-0004 quasi-salted hash |
| `crypt/pgp/` | 230 | 164 | 11 | OpenPGP via ProtonMail go-crypto |
| `crypt/rsa/` | 91 | 101 | 3 | RSA OAEP-SHA256 |
| `crypt/openpgp/` | 191 | 43 | — | Service wrapper, core.Crypt interface |
| `trust/` | 165 | 164 | — | Agent registry, tier management |
| `trust/policy.go` | 238 | 268 | 40+ | Policy engine, 9 capabilities |

**Total**: ~1,938 source LOC, ~1,770 test LOC (47.7% test ratio)

### Dependencies

- `forge.lthn.ai/core/go` — core.E error handling, core.Crypt interface, io.Medium storage
- `github.com/ProtonMail/go-crypto` v1.3.0 — OpenPGP (replaces deprecated golang.org/x/crypto/openpgp)
- `golang.org/x/crypto` v0.48.0 — Argon2, ChaCha20-Poly1305, scrypt, HKDF, bcrypt
- `github.com/cloudflare/circl` v1.6.3 — indirect (elliptic curve via ProtonMail)

### Key Observations

1. **Dual ChaCha20 wrappers** — `crypt/symmetric.go` and `crypt/chachapoly/chachapoly.go` implement nearly identical ChaCha20-Poly1305. The chachapoly sub-package pre-allocates nonce+plaintext capacity (minor optimisation). Consider consolidating.

2. **LTHN hash is NOT constant-time** — `lthn.Verify()` uses direct string comparison (`==`), not `subtle.ConstantTimeCompare`. This is acceptable since LTHN is for content IDs, not passwords — but should be documented clearly.

3. **OpenPGP service has IPC handler** — `openpgp.Service.HandleIPCEvents()` dispatches `"openpgp.create_key_pair"`. This is the only IPC-aware component in go-crypt.

4. **Trust policy decisions are advisory** — `PolicyEngine.Evaluate()` returns `NeedsApproval` but there's no approval queue or workflow. The enforcement layer is expected to live in a higher-level package (go-agentic or go-scm).

5. **Session tokens are in-memory** — No persistence. Suitable for development and single-process deployments, but not distributed systems or crash recovery.

6. **Test naming follows `_Good`/`_Bad`/`_Ugly` pattern** — Consistent with core/go conventions.

### Integration Points

- **go-p2p** → UEPS layer will need crypt/ for consent-gated encryption
- **go-scm** → AgentCI trusts agents via trust/ policy engine
- **go-agentic** → Agent session management via auth/
- **core/go** → OpenPGP service registered via core.Crypt interface

### Security Review Flags

- Argon2id parameters (64MB/3/4) are within OWASP recommended range
- RSA minimum 2048-bit enforced at key generation
- ChaCha20 nonces are 24-byte (XChaCha20-Poly1305), not 12-byte — good, avoids nonce reuse risk
- PGP uses ProtonMail fork (actively maintained, post-quantum research)
- No detected use of `math/rand` — all randomness from `crypto/rand`

---

## Security Audit (Phase 0)

Conducted 2026-02-20. All source files reviewed for cryptographic hygiene.

### 1. Constant-Time Comparisons

| Location | Comparison | Verdict |
|----------|-----------|---------|
| `crypt/hash.go:66` | `subtle.ConstantTimeCompare(computedHash, expectedHash)` | PASS — Argon2id password verification uses constant-time compare |
| `crypt/hmac.go:29` | `hmac.Equal(mac, expected.Sum(nil))` | PASS — HMAC verification uses constant-time compare |
| `crypt/lthn/lthn.go:93` | `Hash(input) == hash` | ACCEPTABLE — LTHN is for content IDs, not passwords. Documented in CLAUDE.md. |
| `auth/auth.go:282` | `a.sessions[token]` | ACCEPTABLE — Map lookup by token as key. 64-hex-char token (256-bit entropy) makes brute-force timing attacks infeasible. |
| `auth/auth.go:387` | `lthn.Verify(password, storedHash)` | **FINDING** — Password verification uses LTHN hash with non-constant-time `==`. See Finding F1 below. |

### 2. Nonce/Randomness Generation

All nonce and random value generation uses `crypto/rand`:

| Location | Purpose | Entropy |
|----------|---------|---------|
| `auth/auth.go:218` | Challenge nonce | 32 bytes (256-bit) via `crypto/rand.Read` |
| `auth/auth.go:439` | Session token | 32 bytes (256-bit) via `crypto/rand.Read` |
| `crypt/kdf.go:55` | Salt generation | 16 bytes (128-bit) via `crypto/rand.Read` |
| `crypt/symmetric.go:22` | ChaCha20 nonce | 24 bytes via `crypto/rand.Read` |
| `crypt/symmetric.go:67` | AES-GCM nonce | 12 bytes via `crypto/rand.Read` |
| `crypt/rsa/rsa.go:25` | RSA key generation | `crypto/rand.Reader` |

**No usage of `math/rand` detected anywhere in the codebase.** PASS.

### 3. PGP Private Key Handling

**FINDING F2**: PGP private key material is NOT zeroed after use. In `pgp.Decrypt()` and `pgp.Sign()`, the private key is decrypted into memory (via `entity.PrivateKey.Decrypt()`) but the decrypted key material remains in memory until garbage collected. The ProtonMail go-crypto library does not provide a `Wipe()` or `Zero()` method on `packet.PrivateKey`, so this is currently a limitation of the upstream library rather than a code defect. Mitigating this would require forking or patching go-crypto.

**Severity**: Low. The Go runtime does not guarantee memory zeroing, and GC-managed languages inherently have this limitation. In practice, an attacker who can read process memory already has full access.

### 4. Error Message Review

No secrets (passwords, tokens, private keys, nonces) leak in error messages. All error strings are generic:
- `"user not found"`, `"invalid password"`, `"session not found"`, `"session expired"`
- `"failed to decrypt"`, `"failed to encrypt"`, `"challenge expired"`
- `"ciphertext too short"`, `"failed to generate nonce"`

The `trust.Register` error includes the agent name (`"invalid tier %d for agent %q"`) which is acceptable — agent names are not secrets.

PASS.

### 5. Session Token Security

- **Entropy**: 32 bytes from `crypto/rand` → 256-bit. Well above the 128-bit minimum.
- **Format**: Hex-encoded → 64-character string. No structural information leaked.
- **Storage**: In-memory `map[string]*Session` behind `sync.RWMutex`.
- **Expiry**: Checked on every `ValidateSession` and `RefreshSession` call. Expired sessions are deleted on access.

PASS.

### Findings

#### F1: LTHN Hash Used for Password Verification (Medium Severity)

`auth.Login()` verifies passwords via `lthn.Verify()` which uses the LTHN quasi-salted hash (RFC-0004) with a non-constant-time string comparison (`==`). LTHN was designed for content identifiers, NOT passwords.

**Impact**: The LTHN hash is deterministic (same input always produces same output) with no random salt. While the quasi-salt derivation adds entropy, it provides weaker protection than Argon2id (`crypt.HashPassword`/`crypt.VerifyPassword` which is available but unused here).

**Timing risk**: The `==` comparison in `lthn.Verify` could theoretically leak information through timing side-channels, though the practical impact is limited because:
1. The comparison is on SHA-256 hex digests (fixed 64 chars)
2. An attacker would need to hash candidate passwords through the LTHN algorithm first

**Recommendation**: Consider migrating password storage from LTHN to Argon2id (`crypt.HashPassword`/`crypt.VerifyPassword`) in a future phase. This would add random salting and constant-time comparison.

#### F2: PGP Private Keys Not Zeroed After Use (Low Severity)

See Section 3 above. Upstream limitation of ProtonMail go-crypto.

#### F3: Trust Policy — Empty ScopedRepos Bypasses Scope Check (Medium Severity)

In `policy.go:122`, the repo scope check is: `if isRepoScoped(cap) && len(agent.ScopedRepos) > 0`. This means a Tier 2 agent with empty `ScopedRepos` (either `nil` or `[]string{}`) is treated as "unrestricted" rather than "no access".

**Impact**: If an admin creates a Tier 2 agent without explicitly setting `ScopedRepos`, the agent gets access to ALL repositories for repo-scoped capabilities (`repo.push`, `pr.create`, `pr.merge`, `secrets.read`).

**Recommendation**: Consider treating empty `ScopedRepos` as "no access" for Tier 2 agents, or requiring explicit `ScopedRepos: []string{"*"}` for unrestricted access. This is a design decision for Phase 3.

#### F4: `go vet` Clean

`go vet ./...` produces no warnings. PASS.

---

## Phase 2: Key Management Implementation (20 Feb 2026)

### F1 Resolution — Argon2id Migration

Finding F1 addressed in `301eac1`. New registrations now use `crypt.HashPassword()` (Argon2id) with random salt and constant-time verification. Hash stored in `.hash` file. Legacy `.lthn` files transparently migrated on successful login: LTHN hash verified → Argon2id re-hash → `.hash` file written. Both paths handled by shared `verifyPassword()` helper.

### Password Verification Dual-Path Design

The `verifyPassword()` helper was extracted after `TestRevokeKey_Bad` failed — new registrations don't write `.lthn` files, so the fallback returned "user not found" instead of "invalid password". The helper tries Argon2id (`.hash`) first, then LTHN (`.lthn`), returning appropriate error messages for each path. Used by both `Login()` and `RevokeKey()`.

### Revocation Design Choice

Chose Option B (JSON record) over Option A (OpenPGP revocation cert). The `Revocation` struct stores `{UserID, Reason, RevokedAt}` as JSON. `IsRevoked()` parses JSON and ignores legacy `"REVOCATION_PLACEHOLDER"` strings. Login and CreateChallenge both check revocation before proceeding.

### Key Rotation Flow

`RotateKeyPair()` implements full key rotation: load private key → decrypt metadata with old password → generate new PGP keypair → re-encrypt metadata → overwrite `.pub/.key/.json/.hash` → invalidate sessions via `store.DeleteByUser()`. The old key material is implicitly discarded (same F2 limitation as PGP — Go GC, not zeroed).

### HardwareKey Interface

Contract-only definition in `hardware.go`. Four methods: `Sign`, `Decrypt`, `GetPublicKey`, `IsAvailable`. Integration points documented but not wired up. The `Authenticator.hardwareKey` field is set via `WithHardwareKey()` option.

### Test Coverage After Phase 2

55 test functions across auth package. Key new tests: Argon2id registration/login (5), key rotation (4), key revocation (6). All pass with `-race`.
