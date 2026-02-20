# Architecture — go-crypt

`forge.lthn.ai/core/go-crypt` provides cryptographic primitives, authentication,
and a trust policy engine for the Lethean agent platform. The module is ~1,938
source LOC across three top-level packages (`auth`, `crypt`, `trust`) and five
sub-packages (`crypt/chachapoly`, `crypt/lthn`, `crypt/pgp`, `crypt/rsa`,
`crypt/openpgp`).

---

## Package Map

```
go-crypt/
├── auth/                   OpenPGP challenge-response authentication, sessions, key management
│   ├── auth.go             Authenticator struct, registration, login, key rotation/revocation
│   ├── session_store.go    SessionStore interface + MemorySessionStore
│   ├── session_store_sqlite.go  SQLiteSessionStore (persistent via go-store)
│   └── hardware.go         HardwareKey interface (contract only, no implementations)
├── crypt/                  Symmetric encryption, key derivation, hashing
│   ├── crypt.go            High-level Encrypt/Decrypt (ChaCha20) and EncryptAES/DecryptAES
│   ├── kdf.go              DeriveKey (Argon2id), DeriveKeyScrypt, HKDF
│   ├── symmetric.go        ChaCha20Encrypt/Decrypt, AESGCMEncrypt/Decrypt
│   ├── hash.go             HashPassword/VerifyPassword (Argon2id), HashBcrypt/VerifyBcrypt
│   ├── hmac.go             HMACSHA256, HMACSHA512, VerifyHMAC
│   ├── checksum.go         SHA256File, SHA512File, SHA256Sum, SHA512Sum
│   ├── chachapoly/         Standalone ChaCha20-Poly1305 AEAD wrapper
│   ├── lthn/               RFC-0004 quasi-salted deterministic hash
│   ├── pgp/                OpenPGP primitives (ProtonMail go-crypto)
│   ├── rsa/                RSA OAEP-SHA256 key generation and encryption
│   └── openpgp/            Service wrapper implementing core.Crypt interface
└── trust/                  Agent trust model and policy engine
    ├── trust.go            Registry, Agent struct, Tier enum
    ├── policy.go           PolicyEngine, 9 capabilities, Evaluate
    ├── approval.go         ApprovalQueue for NeedsApproval workflow
    ├── audit.go            AuditLog — append-only policy evaluation log
    ├── config.go           LoadPolicies/ExportPolicies — JSON config round-trip
    └── scope.go            matchScope — wildcard pattern matching for repo scopes
```

---

## crypt/ — Symmetric Encryption and Hashing

### High-Level API (`crypt.go`)

The entry point for most callers. `Encrypt`/`Decrypt` chain Argon2id key
derivation with ChaCha20-Poly1305 AEAD:

```
Encrypt(plaintext, passphrase):
  1. Generate 16-byte random salt (crypto/rand)
  2. DeriveKey(passphrase, salt) → 32-byte key via Argon2id
  3. ChaCha20Encrypt(plaintext, key) → 24-byte nonce || ciphertext
  4. Output: salt || nonce || ciphertext
```

`EncryptAES`/`DecryptAES` follow the same structure but use AES-256-GCM
with a 12-byte nonce instead of the 24-byte XChaCha20 nonce.

### Key Derivation (`kdf.go`)

Three KDF functions are provided:

| Function | Algorithm | Parameters |
|----------|-----------|------------|
| `DeriveKey` | Argon2id | Memory=64MB, Time=3, Parallelism=4, KeyLen=32 |
| `DeriveKeyScrypt` | scrypt | N=32768, r=8, p=1 |
| `HKDF` | HKDF-SHA256 | Variable key length, optional salt and info |

Argon2id parameters are within the OWASP recommended range for interactive
logins. `HKDF` is used for key expansion when a high-entropy secret is already
available (e.g. deriving sub-keys from a master key).

### Low-Level Symmetric (`symmetric.go`)

`ChaCha20Encrypt` prepends the 24-byte nonce to the ciphertext and returns a
single byte slice. `AESGCMEncrypt` prepends the 12-byte nonce. Both use
`crypto/rand` for nonce generation. The ciphertext format self-describes the
nonce position; callers must not alter the layout between encrypt and decrypt.

### Password Hashing (`hash.go`)

`HashPassword` produces an Argon2id format string:

```
$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
```

`VerifyPassword` re-derives the hash from the stored parameters and uses
`crypto/subtle.ConstantTimeCompare` for the final comparison. This avoids
timing side-channels during password verification.

`HashBcrypt`/`VerifyBcrypt` wrap `golang.org/x/crypto/bcrypt` as a fallback
for systems where bcrypt is required by policy.

### HMAC (`hmac.go`)

`HMACSHA256`/`HMACSHA512` return raw MAC bytes. `VerifyHMAC` uses
`crypto/hmac.Equal` (constant-time) to compare a computed MAC against an
expected value.

### Checksums (`checksum.go`)

`SHA256File`/`SHA512File` compute checksums of files via streaming reads.
`SHA256Sum`/`SHA512Sum` operate on byte slices. All return lowercase hex strings.

### crypt/chachapoly/

A standalone AEAD wrapper with slightly different capacity pre-allocation. The
nonce (24 bytes) is prepended to the ciphertext on encrypt and stripped on
decrypt. This package exists separately from `crypt/symmetric.go` for callers
that import only ChaCha20-Poly1305 without the full `crypt` package.

Note: the two implementations are nearly identical. The main difference is that
`chachapoly` pre-allocates `cap(nonce) + len(plaintext) + overhead` before
appending, which can reduce allocations for small payloads.

### crypt/lthn/

RFC-0004 quasi-salted deterministic hash. The algorithm:

1. Reverse the input string.
2. Apply leet-speak character substitutions (`o`→`0`, `l`→`1`, `e`→`3`,
   `a`→`4`, `s`→`z`, `t`→`7`, and inverses).
3. Concatenate original input with the derived quasi-salt.
4. Return SHA-256 of the concatenation, hex-encoded.

This is deterministic — the same input always produces the same output. It is
designed for content identifiers, cache keys, and deduplication. It is **not**
suitable for password hashing because there is no random salt and the
comparison in `Verify` is not constant-time.

### crypt/pgp/

OpenPGP primitives via `github.com/ProtonMail/go-crypto`:

- `CreateKeyPair(name, email, password)` — generates a DSA primary key with an
  RSA encryption subkey; returns armored public and private keys.
- `Encrypt(plaintext, publicKey)` — produces an armored PGP message.
- `Decrypt(ciphertext, privateKey, password)` — decrypts an armored message.
- `Sign(data, privateKey, password)` — creates a detached armored signature.
- `Verify(data, signature, publicKey)` — verifies a detached signature.

PGP output is Base64-armored, which adds approximately 33% overhead relative
to raw binary. For large payloads consider compression before encryption.

### crypt/rsa/

RSA OAEP-SHA256. `GenerateKeyPair(bits)` generates an RSA keypair (minimum
2048 bit is enforced at the call site). `Encrypt`/`Decrypt` use
`crypto/rsa.EncryptOAEP` with SHA-256. Keys are serialised as PEM blocks.

### crypt/openpgp/

Service wrapper that implements the `core.Crypt` interface from `forge.lthn.ai/core/go`.
Uses RSA-4096 with SHA-256 and AES-256. This is the only IPC-aware component
in go-crypt: `HandleIPCEvents` dispatches the `"openpgp.create_key_pair"` action
when registered with a Core instance.

---

## auth/ — OpenPGP Authentication

### Authenticator

The `Authenticator` struct manages all user identity operations. It takes an
`io.Medium` (from `forge.lthn.ai/core/go`) for storage and an optional
`SessionStore` for session persistence.

```go
a := auth.New(medium,
    auth.WithSessionStore(auth.NewSQLiteSessionStore("/var/lib/app/sessions.db")),
    auth.WithSessionTTL(8*time.Hour),
    auth.WithChallengeTTL(2*time.Minute),
)
```

### Storage Layout

All user artefacts are stored under `users/` on the Medium, keyed by a userID
derived from `lthn.Hash(username)`:

| File | Content |
|------|---------|
| `users/{userID}.pub` | Armored PGP public key |
| `users/{userID}.key` | Armored PGP private key (password-encrypted) |
| `users/{userID}.rev` | JSON revocation record, or legacy placeholder string |
| `users/{userID}.json` | User metadata, PGP-encrypted with the user's public key |
| `users/{userID}.hash` | Argon2id password hash (new registrations and migrated accounts) |
| `users/{userID}.lthn` | Legacy LTHN hash (pre-Phase-2 registrations only) |

### Registration

`Register(username, password)`:

1. Derive `userID = lthn.Hash(username)`.
2. Check `users/{userID}.pub` does not exist.
3. `pgp.CreateKeyPair(userID, ...)` → armored keypair.
4. Write `.pub`, `.key`, `.rev` (placeholder).
5. `crypt.HashPassword(password)` → Argon2id hash string → write `.hash`.
6. JSON-marshal `User` metadata, PGP-encrypt with public key, write `.json`.

### Online Challenge-Response

```
Client                              Server
  |                                    |
  |-- CreateChallenge(userID) -------> |
  |                                    | 1. Generate 32-byte nonce (crypto/rand)
  |                                    | 2. PGP-encrypt nonce with user's public key
  |                                    | 3. Store pending challenge (TTL: 5 min)
  | <-- Challenge{Encrypted} --------- |
  |                                    |
  | (client decrypts nonce, signs it)  |
  |                                    |
  |-- ValidateResponse(signedNonce) -> |
  |                                    | 4. Verify detached PGP signature
  |                                    | 5. Create session (32-byte token, 24h TTL)
  | <-- Session{Token} --------------- |
```

### Air-Gapped (Courier) Mode

`WriteChallengeFile(userID, path)` writes the encrypted challenge as JSON to
the Medium. The client signs the nonce offline. `ReadResponseFile(userID, path)`
reads the armored signature and calls `ValidateResponse` to complete authentication.
This mode supports agents or users who cannot receive live HTTP responses.

### Password-Based Login

`Login(userID, password)` bypasses the PGP challenge-response flow and verifies
the password directly. It supports both hash formats via a dual-path strategy:

1. If `users/{userID}.hash` exists and starts with `$argon2id$`: verify with
   `crypt.VerifyPassword` (constant-time Argon2id comparison).
2. Otherwise fall back to `users/{userID}.lthn`: verify with `lthn.Verify`.
   On success, transparently re-hash the password with Argon2id and write a
   `.hash` file (best-effort, does not fail the login if the write fails).

### Key Management

**Rotation** (`RotateKeyPair(userID, oldPassword, newPassword)`):
- Load and decrypt current metadata using the old private key and password.
- Generate a new PGP keypair.
- Re-encrypt metadata with the new public key.
- Overwrite `.pub`, `.key`, `.json`, `.hash`.
- Invalidate all active sessions for the user via `store.DeleteByUser`.

**Revocation** (`RevokeKey(userID, password, reason)`):
- Verify password (dual-path, same as Login).
- Write a `Revocation{UserID, Reason, RevokedAt}` JSON record to `.rev`.
- Invalidate all sessions.
- `IsRevoked` returns true only when the `.rev` file contains valid JSON with a
  non-zero `RevokedAt`. The legacy `"REVOCATION_PLACEHOLDER"` string is treated
  as non-revoked for backward compatibility.
- Both `Login` and `CreateChallenge` reject revoked users immediately.

**Protected users**: The `"server"` userID cannot be deleted. It holds the
server keypair; deletion would permanently destroy the server's joining data.

### Session Management

Sessions are managed through the `SessionStore` interface:

```go
type SessionStore interface {
    Get(token string) (*Session, error)
    Set(session *Session) error
    Delete(token string) error
    DeleteByUser(userID string) error
    Cleanup() (int, error)
}
```

Two implementations are provided:

| Implementation | Persistence | Concurrency |
|----------------|-------------|-------------|
| `MemorySessionStore` | None (lost on restart) | `sync.RWMutex` |
| `SQLiteSessionStore` | SQLite via go-store | Single mutex (SQLite single-writer) |

Session tokens are 32 bytes from `crypto/rand`, hex-encoded to 64 characters
(256-bit entropy). Expiry is checked on every `ValidateSession` and
`RefreshSession` call; expired sessions are deleted on access. Background
cleanup runs via `StartCleanup(ctx, interval)`.

### Hardware Key Interface

`hardware.go` defines a `HardwareKey` interface for future PKCS#11, YubiKey,
or TPM integration:

```go
type HardwareKey interface {
    Sign(data []byte) ([]byte, error)
    Decrypt(ciphertext []byte) ([]byte, error)
    GetPublicKey() (string, error)
    IsAvailable() bool
}
```

Configured via `WithHardwareKey(hk)`. Integration points are documented in
`auth.go` but not yet wired — there are no concrete implementations in this
module.

---

## trust/ — Agent Trust and Policy Engine

### Registry

`Registry` is a thread-safe map of agent names to `Agent` structs, protected by
`sync.RWMutex`. An `Agent` carries:

- `Name` — unique identifier (e.g. `"Athena"`, `"BugSETI-42"`).
- `Tier` — trust level (1, 2, or 3).
- `ScopedRepos` — repository patterns constraining Tier 2 repo access.
- `RateLimit` — requests per minute (0 = unlimited for Tier 3).
- `TokenExpiresAt` — optional token expiry.

Default rate limits by tier: Tier 1 = 10/min, Tier 2 = 60/min, Tier 3 = unlimited.

### Trust Tiers

| Tier | Name | Default Rate Limit | Typical Agents |
|------|------|-------------------|----------------|
| 3 | Full | Unlimited | Athena, Virgil, Charon |
| 2 | Verified | 60/min | Clotho, Hypnos (scoped repos) |
| 1 | Untrusted | 10/min | BugSETI community instances |

### Capabilities

Nine capabilities are defined:

| Capability | Description |
|------------|-------------|
| `repo.push` | Push commits to a repository |
| `pr.create` | Open a pull request |
| `pr.merge` | Merge a pull request |
| `issue.create` | Create an issue |
| `issue.comment` | Comment on an issue |
| `secrets.read` | Read repository secrets |
| `cmd.privileged` | Run privileged shell commands |
| `workspace.access` | Access another agent's workspace |
| `flows.modify` | Modify CI/CD flow definitions |

### Policy Engine

`NewPolicyEngine(registry)` loads default policies. Evaluation order in
`Evaluate(agentName, cap, repo)`:

1. Agent not in registry → Deny.
2. No policy for agent's tier → Deny.
3. Capability in `Denied` list → Deny.
4. Capability in `RequiresApproval` list → NeedsApproval.
5. Capability in `Allowed` list:
   - If repo-scoped capability and `len(agent.ScopedRepos) > 0`: check repo
     against scope patterns → Deny if no match.
   - Otherwise → Allow.
6. Capability not in any list → Deny.

Default policies by tier:

| Tier | Allowed | RequiresApproval | Denied |
|------|---------|-----------------|--------|
| Full (3) | All 9 capabilities | — | — |
| Verified (2) | repo.push, pr.create, issue.create, issue.comment, secrets.read | pr.merge | workspace.access, flows.modify, cmd.privileged |
| Untrusted (1) | pr.create, issue.comment | — | repo.push, pr.merge, issue.create, secrets.read, cmd.privileged, workspace.access, flows.modify |

### Repo Scope Matching

`matchScope(pattern, repo)` supports three forms:

| Pattern | Matches | Does Not Match |
|---------|---------|----------------|
| `core/go-crypt` | `core/go-crypt` | `core/go-crypt/sub` |
| `core/*` | `core/go-crypt` | `core/go-crypt/sub` |
| `core/**` | `core/go-crypt`, `core/go-crypt/sub` | `other/repo` |

Empty `ScopedRepos` on a Tier 2 agent is treated as unrestricted (no scope
check is applied). See known limitations in `docs/history.md` (Finding F3).

### Approval Queue

`ApprovalQueue` is a thread-safe queue for `NeedsApproval` decisions. It is
separate from the `PolicyEngine` — the engine returns `NeedsApproval` as a
decision, and the caller is responsible for submitting to the queue and polling
for resolution. The queue tracks: submitting agent, capability, repo context,
status (pending/approved/denied), reviewer identity, and timestamps.

### Audit Log

`AuditLog` records every policy evaluation as an `AuditEntry`. Entries are
stored in-memory and optionally streamed as JSON lines to an `io.Writer` for
persistence. `Decision` marshals to/from string (`"allow"`, `"deny"`,
`"needs_approval"`). `EntriesFor(agent)` filters by agent name.

### Dynamic Policy Configuration

Policies can be loaded from JSON and applied at runtime:

```go
engine.ApplyPoliciesFromFile("/etc/agent/policies.json")

// Export current state
engine.ExportPolicies(os.Stdout)
```

JSON format:

```json
{
  "policies": [
    {
      "tier": 1,
      "allowed": ["pr.create", "issue.comment"],
      "denied": ["repo.push", "pr.merge"]
    }
  ]
}
```

`json.Decoder.DisallowUnknownFields()` is set during load to catch
configuration errors early.

---

## Algorithm Reference

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| KDF (primary) | Argon2id | Memory=64MB, Time=3, Parallelism=4, KeyLen=32 |
| KDF (alternative) | scrypt | N=32768, r=8, p=1 |
| KDF (expansion) | HKDF-SHA256 | Variable key length |
| Symmetric (primary) | ChaCha20-Poly1305 | 24-byte nonce (XChaCha20), 32-byte key |
| Symmetric (alternative) | AES-256-GCM | 12-byte nonce, 32-byte key |
| Password hash | Argon2id | Custom `$argon2id$` format string with random salt |
| Password hash (legacy) | LTHN quasi-salted SHA-256 | RFC-0004 (deterministic, no random salt) |
| Password hash (fallback) | Bcrypt | Configurable cost |
| Content ID | LTHN quasi-salted SHA-256 | RFC-0004 |
| Asymmetric | RSA-OAEP-SHA256 | 2048+ bit |
| PGP keypair | DSA primary + RSA subkey | ProtonMail go-crypto |
| PGP service | RSA-4096 + AES-256 + SHA-256 | core.Crypt interface |
| HMAC | HMAC-SHA256 / HMAC-SHA512 | Constant-time verify |
| Challenge nonce | crypto/rand | 32 bytes (256-bit) |
| Session token | crypto/rand | 32 bytes, hex-encoded (64 chars) |

---

## Dependencies

| Module | Version | Role |
|--------|---------|------|
| `forge.lthn.ai/core/go` | local | `core.E` error helper, `core.Crypt` interface, `io.Medium` storage |
| `forge.lthn.ai/core/go-store` | local | SQLite KV store for session persistence |
| `github.com/ProtonMail/go-crypto` | v1.3.0 | OpenPGP (actively maintained fork, post-quantum research) |
| `golang.org/x/crypto` | v0.48.0 | Argon2, ChaCha20-Poly1305, scrypt, HKDF, bcrypt |
| `github.com/cloudflare/circl` | v1.6.3 | Indirect; elliptic curves via ProtonMail |

---

## Integration Points

| Consumer | Package Used | Purpose |
|----------|-------------|---------|
| go-p2p | `crypt/` | UEPS consent-gated encryption |
| go-scm / AgentCI | `trust/` | Agent capability evaluation before CI operations |
| go-agentic | `auth/` | Agent session management |
| core/go | `crypt/openpgp/` | Service registered via `core.Crypt` interface |

---

## Security Notes

1. The LTHN hash (`crypt/lthn`) is **not** suitable for password hashing. It
   is deterministic with no random salt. Use `crypt.HashPassword` (Argon2id).
2. PGP private keys are not zeroed after use. The ProtonMail `go-crypto`
   library does not expose a `Wipe` method. This is a known upstream
   limitation; mitigating it would require forking the library.
3. Empty `ScopedRepos` on a Tier 2 agent currently bypasses the repo scope
   check (treated as unrestricted). Explicit `["*"]` or `["org/**"]` should be
   required for unrestricted Tier 2 access if this design is revisited.
4. The `PolicyEngine` returns decisions but does not enforce the approval
   workflow. A higher-level layer (go-agentic, go-scm) must handle the
   `NeedsApproval` case by routing through the `ApprovalQueue`.
5. The `MemorySessionStore` is the default. Use `WithSessionStore(NewSQLiteSessionStore(path))`
   for persistence across restarts.
