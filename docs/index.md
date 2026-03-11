---
title: go-crypt
description: Cryptographic primitives, authentication, and trust policy engine for the Lethean agent platform.
---

# go-crypt

**Module**: `forge.lthn.ai/core/go-crypt`
**Licence**: EUPL-1.2
**Language**: Go 1.26

Cryptographic primitives, authentication, and trust policy engine for the
Lethean agent platform. Provides symmetric encryption, password hashing,
OpenPGP authentication with both online and air-gapped modes, RSA key
management, deterministic content hashing, and a three-tier agent access
control system with an audit log and approval queue.

## Quick Start

```go
import (
    "forge.lthn.ai/core/go-crypt/crypt"
    "forge.lthn.ai/core/go-crypt/auth"
    "forge.lthn.ai/core/go-crypt/trust"
)
```

### Encrypt and Decrypt Data

The default cipher is XChaCha20-Poly1305 with Argon2id key derivation. A
random salt and nonce are generated automatically and prepended to the
ciphertext.

```go
// Encrypt with ChaCha20-Poly1305 + Argon2id KDF
ciphertext, err := crypt.Encrypt(plaintext, []byte("my passphrase"))

// Decrypt
plaintext, err := crypt.Decrypt(ciphertext, []byte("my passphrase"))

// Or use AES-256-GCM instead
ciphertext, err := crypt.EncryptAES(plaintext, []byte("my passphrase"))
plaintext, err := crypt.DecryptAES(ciphertext, []byte("my passphrase"))
```

### Hash and Verify Passwords

```go
// Hash with Argon2id (recommended)
hash, err := crypt.HashPassword("hunter2")
// Returns: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>

// Verify (constant-time comparison)
match, err := crypt.VerifyPassword("hunter2", hash)
```

### OpenPGP Authentication

```go
// Create an authenticator backed by a storage medium
a := auth.New(medium,
    auth.WithSessionStore(sqliteStore),
    auth.WithSessionTTL(8 * time.Hour),
)

// Register a user (generates PGP keypair, stores credentials)
user, err := a.Register("alice", "password123")

// Password-based login (bypasses PGP challenge-response)
session, err := a.Login(userID, "password123")

// Validate a session token
session, err := a.ValidateSession(token)
```

### Trust Policy Evaluation

```go
// Set up a registry and register agents
registry := trust.NewRegistry()
registry.Register(trust.Agent{
    Name: "Athena",
    Tier: trust.TierFull,
})
registry.Register(trust.Agent{
    Name:        "Clotho",
    Tier:        trust.TierVerified,
    ScopedRepos: []string{"core/*"},
})

// Evaluate capabilities
engine := trust.NewPolicyEngine(registry)
result := engine.Evaluate("Athena", trust.CapPushRepo, "core/go-crypt")
// result.Decision == trust.Allow

result = engine.Evaluate("Clotho", trust.CapMergePR, "core/go-crypt")
// result.Decision == trust.NeedsApproval
```

## Package Layout

| Package | Import Path | Description |
|---------|-------------|-------------|
| `crypt` | `go-crypt/crypt` | High-level encrypt/decrypt (ChaCha20 + AES), password hashing, HMAC, checksums, key derivation |
| `crypt/chachapoly` | `go-crypt/crypt/chachapoly` | Standalone ChaCha20-Poly1305 AEAD wrapper |
| `crypt/lthn` | `go-crypt/crypt/lthn` | RFC-0004 quasi-salted deterministic hash for content identifiers |
| `crypt/pgp` | `go-crypt/crypt/pgp` | OpenPGP key generation, encryption, decryption, signing, verification |
| `crypt/rsa` | `go-crypt/crypt/rsa` | RSA-OAEP-SHA256 key generation and encryption (2048+ bit) |
| `crypt/openpgp` | `go-crypt/crypt/openpgp` | Service wrapper implementing the `core.Crypt` interface with IPC support |
| `auth` | `go-crypt/auth` | OpenPGP challenge-response authentication, session management, key rotation/revocation |
| `trust` | `go-crypt/trust` | Agent trust model, policy engine, approval queue, audit log |
| `cmd/crypt` | `go-crypt/cmd/crypt` | CLI commands: `crypt encrypt`, `crypt decrypt`, `crypt hash`, `crypt keygen`, `crypt checksum` |

## CLI Commands

The `cmd/crypt` package registers a `crypt` command group with the `core` CLI:

```bash
# Encrypt a file (ChaCha20-Poly1305 by default)
core crypt encrypt myfile.txt -p "passphrase"
core crypt encrypt myfile.txt --aes -p "passphrase"

# Decrypt
core crypt decrypt myfile.txt.enc -p "passphrase"

# Hash a password
core crypt hash "my password"           # Argon2id
core crypt hash "my password" --bcrypt  # Bcrypt

# Verify a password against a hash
core crypt hash "my password" --verify '$argon2id$v=19$...'

# Generate a random key
core crypt keygen                       # 32 bytes, hex
core crypt keygen -l 64 --base64       # 64 bytes, base64

# Compute file checksums
core crypt checksum myfile.txt          # SHA-256
core crypt checksum myfile.txt --sha512
core crypt checksum myfile.txt --verify "abc123..."
```

## Dependencies

| Module | Role |
|--------|------|
| `forge.lthn.ai/core/go` | Framework: `core.E` error helper, `core.Crypt` interface, `io.Medium` storage abstraction |
| `forge.lthn.ai/core/go-store` | SQLite KV store for persistent session storage |
| `forge.lthn.ai/core/go-io` | `io.Medium` interface used by the auth package |
| `forge.lthn.ai/core/go-log` | Contextual error wrapping via `core.E()` |
| `forge.lthn.ai/core/cli` | CLI framework for the `cmd/crypt` commands |
| `github.com/ProtonMail/go-crypto` | OpenPGP implementation (actively maintained, post-quantum research) |
| `golang.org/x/crypto` | Argon2id, ChaCha20-Poly1305, scrypt, HKDF, bcrypt |
| `github.com/stretchr/testify` | Test assertions (`assert`, `require`) |

No C toolchain or CGo is required. All cryptographic operations use pure Go
implementations.

## Further Reading

- [Architecture](architecture.md) -- internals, data flow, algorithm reference
- [Development](development.md) -- building, testing, contributing
- [History](history.md) -- completed phases, security audit findings, known limitations
