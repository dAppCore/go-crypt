---
title: Architecture
description: Internal design, key types, data flow, and algorithm reference for go-crypt.
---

# Architecture

`forge.lthn.ai/core/go-crypt` is organised into three top-level packages
(`crypt`, `auth`, `trust`) and five sub-packages under `crypt/`. Each
package is self-contained and can be imported independently.

```
go-crypt/
├── auth/                   OpenPGP challenge-response authentication
│   ├── auth.go             Authenticator: registration, login, key rotation, revocation
│   ├── session_store.go    SessionStore interface + MemorySessionStore
│   ├── session_store_sqlite.go   SQLiteSessionStore (persistent via go-store)
│   └── hardware.go         HardwareKey interface (contract only, no implementations yet)
├── crypt/                  Symmetric encryption, hashing, key derivation
│   ├── crypt.go            High-level Encrypt/Decrypt and EncryptAES/DecryptAES
│   ├── kdf.go              Key derivation: Argon2id, scrypt, HKDF-SHA256
│   ├── symmetric.go        Low-level ChaCha20-Poly1305 and AES-256-GCM
│   ├── hash.go             Password hashing: Argon2id and bcrypt
│   ├── hmac.go             HMAC-SHA256, HMAC-SHA512, constant-time verify
│   ├── checksum.go         SHA-256 and SHA-512 file/data checksums
│   ├── chachapoly/         Standalone ChaCha20-Poly1305 AEAD wrapper
│   ├── lthn/               RFC-0004 quasi-salted deterministic hash
│   ├── pgp/                OpenPGP primitives (ProtonMail go-crypto)
│   ├── rsa/                RSA-OAEP-SHA256 key generation and encryption
│   └── openpgp/            Service wrapper implementing core.Crypt interface
├── trust/                  Agent trust model and policy engine
│   ├── trust.go            Registry, Agent struct, Tier enum
│   ├── policy.go           PolicyEngine, capabilities, Evaluate()
│   ├── approval.go         ApprovalQueue for NeedsApproval decisions
│   ├── audit.go            AuditLog: append-only policy evaluation log
│   └── config.go           JSON policy configuration: load, apply, export
└── cmd/
    └── crypt/              CLI commands registered with core CLI
```

---

## crypt/ -- Symmetric Encryption and Hashing

### High-Level API

The `crypt.Encrypt` and `crypt.Decrypt` functions are the primary entry
points. They chain Argon2id key derivation with XChaCha20-Poly1305 AEAD
encryption. A random salt is generated and prepended to the output so that
callers need only track the passphrase.

```
Encrypt(plaintext, passphrase) -> salt || nonce || ciphertext

  1. Generate 16-byte random salt (crypto/rand)
  2. DeriveKey(passphrase, salt) -> 32-byte key via Argon2id
  3. ChaCha20Encrypt(plaintext, key) -> 24-byte nonce || ciphertext
  4. Prepend salt to the result
```

`EncryptAES` and `DecryptAES` follow the same pattern but use AES-256-GCM
with a 12-byte nonce instead of the 24-byte XChaCha20 nonce.

Both ciphers produce self-describing byte layouts. Callers must not alter
the layout between encrypt and decrypt.

| Function | Cipher | Nonce | Wire Format |
|----------|--------|-------|-------------|
| `Encrypt` / `Decrypt` | XChaCha20-Poly1305 | 24 bytes | salt(16) + nonce(24) + ciphertext |
| `EncryptAES` / `DecryptAES` | AES-256-GCM | 12 bytes | salt(16) + nonce(12) + ciphertext |

### Key Derivation (kdf.go)

Three key derivation functions serve different use cases:

| Function | Algorithm | Parameters | Use Case |
|----------|-----------|------------|----------|
| `DeriveKey` | Argon2id | Memory=64MB, Time=3, Parallelism=4, KeyLen=32 | Primary KDF for passphrase-based encryption |
| `DeriveKeyScrypt` | scrypt | N=32768, r=8, p=1 | Alternative KDF where Argon2id is unavailable |
| `HKDF` | HKDF-SHA256 | Variable key length, optional salt/info | Key expansion from high-entropy secrets |

The Argon2id parameters sit within the OWASP-recommended range for
interactive logins. `HKDF` is intended for deriving sub-keys from a master
key that already has high entropy; it should not be used directly with
low-entropy passphrases.

### Low-Level Symmetric Ciphers (symmetric.go)

`ChaCha20Encrypt` and `AESGCMEncrypt` each generate a random nonce via
`crypto/rand` and prepend it to the ciphertext. The corresponding decrypt
functions extract the nonce from the front of the byte slice.

```go
// ChaCha20-Poly1305: 32-byte key required
ciphertext, err := crypt.ChaCha20Encrypt(plaintext, key)
plaintext, err := crypt.ChaCha20Decrypt(ciphertext, key)

// AES-256-GCM: 32-byte key required
ciphertext, err := crypt.AESGCMEncrypt(plaintext, key)
plaintext, err := crypt.AESGCMDecrypt(ciphertext, key)
```

### Password Hashing (hash.go)

`HashPassword` produces a self-describing Argon2id hash string:

```
$argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
```

`VerifyPassword` re-derives the hash from the parameters encoded in the
string and uses `crypto/subtle.ConstantTimeCompare` for the final
comparison. This prevents timing side-channels during password verification.

`HashBcrypt` and `VerifyBcrypt` wrap `golang.org/x/crypto/bcrypt` as a
fallback for environments where bcrypt is mandated by policy.

### HMAC (hmac.go)

Three functions for message authentication codes:

- `HMACSHA256(message, key)` -- returns raw 32-byte MAC.
- `HMACSHA512(message, key)` -- returns raw 64-byte MAC.
- `VerifyHMAC(message, key, mac, hashFunc)` -- constant-time verification
  using `crypto/hmac.Equal`.

### Checksums (checksum.go)

File checksums use streaming reads to handle arbitrarily large files without
loading them entirely into memory:

```go
hash, err := crypt.SHA256File("/path/to/file")  // hex string
hash, err := crypt.SHA512File("/path/to/file")  // hex string

// In-memory checksums
hash := crypt.SHA256Sum(data)  // hex string
hash := crypt.SHA512Sum(data)  // hex string
```

### crypt/chachapoly/

A standalone ChaCha20-Poly1305 package that can be imported independently.
It pre-allocates `cap(nonce) + len(plaintext) + overhead` before appending,
which reduces allocations for small payloads.

```go
import "forge.lthn.ai/core/go-crypt/crypt/chachapoly"

ciphertext, err := chachapoly.Encrypt(plaintext, key)  // key must be 32 bytes
plaintext, err := chachapoly.Decrypt(ciphertext, key)
```

This is functionally identical to `crypt.ChaCha20Encrypt` and exists as a
separate import path for callers that only need the AEAD primitive.

### crypt/lthn/ -- RFC-0004 Deterministic Hash

The LTHN hash produces a deterministic, verifiable identifier from any
input string. The algorithm:

1. Reverse the input string.
2. Apply "leet speak" character substitutions (`o` to `0`, `l` to `1`,
   `e` to `3`, `a` to `4`, `s` to `z`, `t` to `7`, and their inverses).
3. Concatenate the original input with the derived quasi-salt.
4. Return the SHA-256 digest, hex-encoded (64 characters).

```go
import "forge.lthn.ai/core/go-crypt/crypt/lthn"

hash := lthn.Hash("hello")
valid := lthn.Verify("hello", hash)  // true
```

The substitution map can be customised via `lthn.SetKeyMap()` for
application-specific derivation.

**Important**: LTHN is designed for content identifiers, cache keys, and
deduplication. It is not suitable for password hashing because it uses no
random salt and the comparison in `Verify` uses `subtle.ConstantTimeCompare`
but the hash itself is deterministic and fast.

### crypt/pgp/ -- OpenPGP Primitives

Full OpenPGP support via `github.com/ProtonMail/go-crypto`:

```go
import "forge.lthn.ai/core/go-crypt/crypt/pgp"

// Generate a keypair (private key optionally password-protected)
kp, err := pgp.CreateKeyPair("Alice", "alice@example.com", "password")
// kp.PublicKey  -- armored PGP public key
// kp.PrivateKey -- armored PGP private key

// Encrypt data for a recipient
ciphertext, err := pgp.Encrypt(data, kp.PublicKey)

// Decrypt with private key
plaintext, err := pgp.Decrypt(ciphertext, kp.PrivateKey, "password")

// Sign data (detached armored signature)
signature, err := pgp.Sign(data, kp.PrivateKey, "password")

// Verify a detached signature
err := pgp.Verify(data, signature, kp.PublicKey)
```

All PGP output is Base64-armored, adding approximately 33% overhead
relative to raw binary. For large payloads, consider compression before
encryption.

### crypt/rsa/ -- RSA-OAEP

RSA encryption with OAEP-SHA256 padding. A minimum key size of 2048 bits
is enforced at the API level.

```go
import "forge.lthn.ai/core/go-crypt/crypt/rsa"

svc := rsa.NewService()

// Generate a keypair (PEM-encoded)
pubKey, privKey, err := svc.GenerateKeyPair(4096)

// Encrypt / Decrypt with optional label
ciphertext, err := svc.Encrypt(pubKey, plaintext, label)
plaintext, err := svc.Decrypt(privKey, ciphertext, label)
```

### crypt/openpgp/ -- Core Service Integration

A service wrapper that implements the `core.Crypt` interface from
`forge.lthn.ai/core/go`. This is the only component in go-crypt that
integrates with the Core framework's IPC system.

```go
import "forge.lthn.ai/core/go-crypt/crypt/openpgp"

// Register as a Core service
core.New(core.WithService(openpgp.New))

// Handles the "openpgp.create_key_pair" IPC action
```

The service generates RSA-4096 keypairs with SHA-256 hashing and AES-256
encryption for private key protection.

---

## auth/ -- OpenPGP Authentication

### Authenticator

The `Authenticator` struct is the central type for user identity operations.
It takes an `io.Medium` for storage and supports functional options for
configuration.

```go
a := auth.New(medium,
    auth.WithSessionStore(sqliteStore),
    auth.WithSessionTTL(8 * time.Hour),
    auth.WithChallengeTTL(2 * time.Minute),
    auth.WithHardwareKey(yubikey),  // future: hardware-backed crypto
)
```

### Storage Layout

All user artefacts are stored under `users/` on the Medium, keyed by a
userID derived from `lthn.Hash(username)`:

| File | Content |
|------|---------|
| `users/{userID}.pub` | Armored PGP public key |
| `users/{userID}.key` | Armored PGP private key (password-encrypted) |
| `users/{userID}.rev` | JSON revocation record, or legacy placeholder |
| `users/{userID}.json` | User metadata (PGP-encrypted with user's public key) |
| `users/{userID}.hash` | Argon2id password hash |
| `users/{userID}.lthn` | Legacy LTHN hash (migrated transparently on login) |

### Registration Flow

`Register(username, password)`:

1. Derive `userID = lthn.Hash(username)`.
2. Check that `users/{userID}.pub` does not already exist.
3. Generate a PGP keypair via `pgp.CreateKeyPair`.
4. Store `.pub`, `.key`, `.rev` (placeholder).
5. Hash the password with Argon2id and store as `.hash`.
6. Marshal user metadata as JSON, encrypt with the user's PGP public key,
   store as `.json`.

### Online Challenge-Response Flow

This is the primary authentication mechanism. It proves that the client
holds the private key corresponding to a registered public key.

```
Client                              Server
  |                                    |
  |-- CreateChallenge(userID) -------> |
  |                                    | 1. Generate 32-byte nonce (crypto/rand)
  |                                    | 2. PGP-encrypt nonce with user's public key
  |                                    | 3. Store pending challenge (default TTL: 5 min)
  | <-- Challenge{Encrypted} --------- |
  |                                    |
  | (decrypt nonce, sign with privkey) |
  |                                    |
  |-- ValidateResponse(signedNonce) -> |
  |                                    | 4. Verify detached PGP signature
  |                                    | 5. Create session (32-byte token, default 24h TTL)
  | <-- Session{Token} --------------- |
```

### Air-Gapped (Courier) Mode

For agents that cannot receive live HTTP responses:

- `WriteChallengeFile(userID, path)` writes the encrypted challenge as JSON
  to the Medium.
- The client signs the nonce offline.
- `ReadResponseFile(userID, path)` reads the armored signature and validates
  it, completing the authentication.

### Password-Based Login

`Login(userID, password)` bypasses the PGP challenge-response flow. It
supports both hash formats with automatic migration:

1. If `.hash` exists and starts with `$argon2id$`: verify with
   constant-time Argon2id comparison.
2. Otherwise, fall back to `.lthn` and verify with `lthn.Verify`.
   On success, re-hash with Argon2id and write a `.hash` file
   (best-effort -- login succeeds even if the migration write fails).

### Key Management

**Rotation** via `RotateKeyPair(userID, oldPassword, newPassword)`:

- Decrypt current metadata with the old private key and password.
- Generate a new PGP keypair protected by the new password.
- Re-encrypt metadata with the new public key.
- Overwrite `.pub`, `.key`, `.json`, `.hash`.
- Invalidate all active sessions for the user.

**Revocation** via `RevokeKey(userID, password, reason)`:

- Verify the password (tries Argon2id first, then LTHN).
- Write a `Revocation{UserID, Reason, RevokedAt}` JSON record to `.rev`.
- Invalidate all sessions.
- Both `Login` and `CreateChallenge` immediately reject revoked users.

**Protected users**: The `"server"` userID cannot be deleted. It holds the
server keypair; deleting it would permanently destroy the server's joining
data.

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

| Store | Persistence | Concurrency Model |
|-------|-------------|-------------------|
| `MemorySessionStore` | None (lost on restart) | `sync.RWMutex` with defensive copies |
| `SQLiteSessionStore` | SQLite via go-store | Single `sync.Mutex` (SQLite single-writer) |

Session tokens are 32 bytes from `crypto/rand`, hex-encoded to 64
characters (256-bit entropy). Expired sessions are cleaned up either on
access or via the `StartCleanup(ctx, interval)` background goroutine.

### Hardware Key Interface

`hardware.go` defines a `HardwareKey` interface for future PKCS#11,
YubiKey, or TPM integration:

```go
type HardwareKey interface {
    Sign(data []byte) ([]byte, error)
    Decrypt(ciphertext []byte) ([]byte, error)
    GetPublicKey() (string, error)
    IsAvailable() bool
}
```

Configured via `WithHardwareKey(hk)`. No concrete implementations exist
yet -- this is a contract-only definition.

---

## trust/ -- Agent Trust and Policy Engine

### Trust Tiers

Agents are assigned one of three trust tiers:

| Tier | Name | Value | Default Rate Limit | Typical Agents |
|------|------|-------|-------------------|----------------|
| Full | `TierFull` | 3 | Unlimited | Athena, Virgil, Charon |
| Verified | `TierVerified` | 2 | 60 req/min | Clotho, Hypnos |
| Untrusted | `TierUntrusted` | 1 | 10 req/min | Community instances |

### Registry

`Registry` is a thread-safe map of agent names to `Agent` structs:

```go
registry := trust.NewRegistry()
err := registry.Register(trust.Agent{
    Name:        "Clotho",
    Tier:        trust.TierVerified,
    ScopedRepos: []string{"core/*"},
    RateLimit:   30,
})

agent := registry.Get("Clotho")
agents := registry.List()      // snapshot slice
for a := range registry.ListSeq() { ... }  // iterator
```

### Capabilities

Nine capabilities are defined as typed constants:

| Capability | Constant | Description |
|------------|----------|-------------|
| `repo.push` | `CapPushRepo` | Push commits to a repository |
| `pr.create` | `CapCreatePR` | Open a pull request |
| `pr.merge` | `CapMergePR` | Merge a pull request |
| `issue.create` | `CapCreateIssue` | Create an issue |
| `issue.comment` | `CapCommentIssue` | Comment on an issue |
| `secrets.read` | `CapReadSecrets` | Read repository secrets |
| `cmd.privileged` | `CapRunPrivileged` | Run privileged shell commands |
| `workspace.access` | `CapAccessWorkspace` | Access another agent's workspace |
| `flows.modify` | `CapModifyFlows` | Modify CI/CD flow definitions |

### Policy Engine

`NewPolicyEngine(registry)` creates an engine with default policies.
`Evaluate` returns one of three decisions:

```go
engine := trust.NewPolicyEngine(registry)
result := engine.Evaluate("Clotho", trust.CapPushRepo, "core/go-crypt")

switch result.Decision {
case trust.Allow:
    // Proceed
case trust.Deny:
    // Reject with result.Reason
case trust.NeedsApproval:
    // Submit to ApprovalQueue
}
```

**Evaluation order**:

1. Agent not in registry -- `Deny`.
2. No policy for the agent's tier -- `Deny`.
3. Capability in the `Denied` list -- `Deny`.
4. Capability in the `RequiresApproval` list -- `NeedsApproval`.
5. Capability in the `Allowed` list:
   - If the capability is repo-scoped and the agent has `ScopedRepos`:
     check the repo against scope patterns. No match -- `Deny`.
   - Otherwise -- `Allow`.
6. Capability not in any list -- `Deny`.

**Default policies by tier**:

| Tier | Allowed | Requires Approval | Denied |
|------|---------|-------------------|--------|
| Full (3) | All 9 capabilities | -- | -- |
| Verified (2) | repo.push, pr.create, issue.create, issue.comment, secrets.read | pr.merge | workspace.access, flows.modify, cmd.privileged |
| Untrusted (1) | pr.create, issue.comment | -- | repo.push, pr.merge, issue.create, secrets.read, cmd.privileged, workspace.access, flows.modify |

### Repo Scope Matching

Tier 2 agents can have their repository access restricted via `ScopedRepos`.
Three pattern types are supported:

| Pattern | Matches | Does Not Match |
|---------|---------|----------------|
| `core/go-crypt` | `core/go-crypt` (exact) | `core/go-crypt/sub` |
| `core/*` | `core/go-crypt`, `core/php` | `core/go-crypt/sub`, `other/repo` |
| `core/**` | `core/go-crypt`, `core/php/sub`, `core/a/b/c` | `other/repo` |

Wildcards are only supported at the end of patterns.

### Approval Queue

When the policy engine returns `NeedsApproval`, the caller is responsible
for submitting the request to an `ApprovalQueue`:

```go
queue := trust.NewApprovalQueue()

// Submit a request
id, err := queue.Submit("Clotho", trust.CapMergePR, "core/go-crypt")

// Review pending requests
for _, req := range queue.Pending() { ... }

// Approve or deny
queue.Approve(id, "admin", "Looks good")
queue.Deny(id, "admin", "Not yet authorised")

// Check status
req := queue.Get(id)  // req.Status == trust.ApprovalApproved
```

The queue is thread-safe and tracks timestamps, reviewer identity, and
reasons for each decision.

### Audit Log

Every policy evaluation can be recorded in an append-only audit log:

```go
log := trust.NewAuditLog(os.Stdout)  // or nil for in-memory only

result := engine.Evaluate("Clotho", trust.CapPushRepo, "core/php")
log.Record(result, "core/php")

// Query entries
entries := log.Entries()
agentEntries := log.EntriesFor("Clotho")
for e := range log.EntriesForSeq("Clotho") { ... }
```

When an `io.Writer` is provided, each entry is serialised as a JSON line
for persistent storage. The `Decision` type marshals to and from string
values (`"allow"`, `"deny"`, `"needs_approval"`).

### Dynamic Policy Configuration

Policies can be loaded from JSON at runtime:

```go
// Load from file
engine.ApplyPoliciesFromFile("/etc/agent/policies.json")

// Load from reader
engine.ApplyPolicies(reader)

// Export current policies
engine.ExportPolicies(os.Stdout)
```

JSON format:

```json
{
  "policies": [
    {
      "tier": 2,
      "allowed": ["repo.push", "pr.create", "issue.create"],
      "requires_approval": ["pr.merge"],
      "denied": ["cmd.privileged", "workspace.access"]
    }
  ]
}
```

The JSON decoder uses `DisallowUnknownFields()` to catch configuration
errors early.

---

## Algorithm Reference

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| KDF (primary) | Argon2id | Memory=64MB, Time=3, Parallelism=4, KeyLen=32 |
| KDF (alternative) | scrypt | N=32768, r=8, p=1 |
| KDF (expansion) | HKDF-SHA256 | Variable key length |
| Symmetric (primary) | XChaCha20-Poly1305 | 24-byte nonce, 32-byte key |
| Symmetric (alternative) | AES-256-GCM | 12-byte nonce, 32-byte key |
| Password hash (primary) | Argon2id | `$argon2id$` format with random 16-byte salt |
| Password hash (fallback) | bcrypt | Configurable cost |
| Content ID | LTHN quasi-salted SHA-256 | RFC-0004 (deterministic, no random salt) |
| Asymmetric | RSA-OAEP-SHA256 | 2048+ bit keys |
| PGP (pgp/) | DSA primary + RSA subkey | ProtonMail go-crypto |
| PGP (openpgp/) | RSA-4096 + AES-256 + SHA-256 | core.Crypt interface |
| HMAC | HMAC-SHA256 / HMAC-SHA512 | Constant-time verification |
| Challenge nonce | crypto/rand | 32 bytes (256-bit entropy) |
| Session token | crypto/rand | 32 bytes, hex-encoded (64 chars) |

---

## Security Notes

1. The LTHN hash (`crypt/lthn`) is **not** suitable for password hashing.
   It is deterministic with no random salt. Use `crypt.HashPassword`
   (Argon2id) for passwords.

2. PGP private keys are not zeroed after use. The ProtonMail go-crypto
   library does not expose a `Wipe` method. This is a known upstream
   limitation.

3. Empty `ScopedRepos` on a Tier 2 agent currently bypasses the repo
   scope check (treated as unrestricted). Explicit `["*"]` or
   `["org/**"]` should be required for unrestricted Tier 2 access if
   this design is revisited.

4. The `PolicyEngine` returns decisions but does not enforce the approval
   workflow. A higher-level layer must handle `NeedsApproval` by routing
   through the `ApprovalQueue`.

5. All randomness uses `crypto/rand`. Never use `math/rand` for
   cryptographic purposes in this codebase.

6. Error messages never include secret material. Strings are kept generic:
   `"invalid password"`, `"session not found"`, `"failed to decrypt"`.
