# CLAUDE.md — go-crypt Domain Expert Guide

You are a dedicated domain expert for `forge.lthn.ai/core/go-crypt`. Virgil (in core/go) orchestrates your work via TODO.md. Pick up tasks in phase order, mark `[x]` when done, commit and push.

## What This Package Does

Cryptographic primitives, authentication, and trust policy engine. ~3.7K LOC across 28 Go files. Provides:

- **Symmetric encryption** — ChaCha20-Poly1305 and AES-256-GCM with Argon2id key derivation
- **OpenPGP authentication** — Challenge-response (online + air-gapped courier mode)
- **Password hashing** — Argon2id (primary) + Bcrypt (fallback)
- **Trust policy engine** — 3-tier agent access control with capability evaluation
- **RSA** — OAEP-SHA256 key generation and encryption (2048+ bit)
- **LTHN hash** — RFC-0004 quasi-salted deterministic hash (content IDs, NOT passwords)

## Commands

```bash
go test ./...                    # Run all tests
go test -v -run TestName ./...   # Single test
go test -race ./...              # Race detector
go vet ./...                     # Static analysis
```

## Local Dependencies

| Module | Local Path | Notes |
|--------|-----------|-------|
| `forge.lthn.ai/core/go` | `../go` | Framework (core.E, core.Crypt, io.Medium) |
| `forge.lthn.ai/core/go-store` | `../go-store` | SQLite KV store (session persistence) |

**Do NOT change the replace directive path.** Use go.work for local resolution if needed.

## Architecture

### auth/ — OpenPGP Challenge-Response + Password Auth (455 LOC)

`Authenticator` backed by `io.Medium` storage abstraction.

**Registration flow**: Generate PGP keypair → store `.pub`, `.key`, `.rev`, `.json`, `.lthn` files under `users/{userID}/`.

**Online challenge-response**:
1. `CreateChallenge(userID)` → 32-byte random nonce, encrypted with user's public key
2. Client decrypts nonce, signs it with private key
3. `ValidateResponse(userID, signedNonce)` → verifies signature, issues 24h session token

**Air-gapped (courier) mode**:
1. `WriteChallengeFile(userID, path)` → JSON with encrypted nonce
2. Client signs offline
3. `ReadResponseFile(userID, path)` → verify, issue session

**Session management**: Abstracted behind `SessionStore` interface. 32-byte hex tokens, 24h TTL. `ValidateSession`, `RefreshSession`, `RevokeSession`. Two implementations:
- `MemorySessionStore` — in-memory `sync.RWMutex`-protected map (default, sessions lost on restart)
- `SQLiteSessionStore` — persistent via go-store (SQLite KV), mutex-serialised for single-writer safety

Configure via `WithSessionStore(store)` option. Background cleanup via `StartCleanup(ctx, interval)`.

**Protected users**: `"server"` cannot be deleted.

### crypt/ — Symmetric Encryption & Hashing (624 LOC)

| File | LOC | Purpose |
|------|-----|---------|
| `crypt.go` | 90 | High-level `Encrypt`/`Decrypt` (ChaCha20 + Argon2id) and AES-256-GCM variant |
| `kdf.go` | 60 | `DeriveKey` (Argon2id: 64MB/3 iter/4 threads), `DeriveKeyScrypt`, `HKDF` |
| `symmetric.go` | 100 | Low-level `ChaCha20Encrypt`/`Decrypt`, `AESGCMEncrypt`/`Decrypt` |
| `hash.go` | 89 | `HashPassword`/`VerifyPassword` (Argon2id format string), Bcrypt |
| `hmac.go` | 30 | `HMACSHA256`/`512`, constant-time `VerifyHMAC` |
| `checksum.go` | 55 | `SHA256File`, `SHA512File`, `SHA256Sum`, `SHA512Sum` |

#### crypt/chachapoly/ (50 LOC)
Standalone ChaCha20-Poly1305 AEAD wrapper. 24-byte nonce prepended to ciphertext.

#### crypt/lthn/ (94 LOC)
RFC-0004 quasi-salted hash. Deterministic: reverse input → leet-speak substitution → SHA-256. For content IDs and deduplication. **NOT for passwords.**

#### crypt/pgp/ (230 LOC)
OpenPGP primitives via ProtonMail `go-crypto`:
- `CreateKeyPair(name, email, password)` → armored DSA primary + RSA subkey
- `Encrypt`/`Decrypt` → armored PGP messages
- `Sign`/`Verify` → detached signatures

#### crypt/rsa/ (91 LOC)
RSA key generation (2048+ bit), OAEP-SHA256 encrypt/decrypt, PEM encoding.

#### crypt/openpgp/ (191 LOC)
Service wrapper implementing `core.Crypt` interface. RSA-4096, SHA-256, AES-256. Registers IPC handler for `"openpgp.create_key_pair"`.

### trust/ — Agent Trust & Policy Engine (403 LOC)

| File | LOC | Purpose |
|------|-----|---------|
| `trust.go` | 165 | `Registry` (thread-safe agent store), `Agent` struct, `Tier` enum |
| `policy.go` | 238 | `PolicyEngine`, 9 capabilities, `Evaluate` → Allow/Deny/NeedsApproval |

**Trust tiers**:
| Tier | Name | Rate Limit | Example Agents |
|------|------|-----------|----------------|
| 3 | Full | Unlimited | Athena, Virgil, Charon |
| 2 | Verified | 60/min | Clotho, Hypnos (scoped repos) |
| 1 | Untrusted | 10/min | BugSETI instances |

**9 Capabilities**: `repo.push`, `pr.merge`, `pr.create`, `issue.create`, `issue.comment`, `secrets.read`, `cmd.privileged`, `workspace.access`, `flows.modify`

**Evaluation order**: Agent exists → policy exists → explicitly denied → requires approval → allowed (with repo scope check).

## Algorithm Reference

| Component | Algorithm | Parameters |
|-----------|-----------|-----------|
| KDF (primary) | Argon2id | Time=3, Memory=64MB, Parallelism=4 |
| KDF (alt) | scrypt | N=32768, r=8, p=1 |
| KDF (expand) | HKDF-SHA256 | Variable key length |
| Symmetric | ChaCha20-Poly1305 | 24-byte nonce, 32-byte key |
| Symmetric (alt) | AES-256-GCM | 12-byte nonce, 32-byte key |
| Password hash | Argon2id | Custom format string |
| Password hash (alt) | Bcrypt | Default cost |
| Deterministic hash | SHA-256 + quasi-salt | RFC-0004 |
| Asymmetric | RSA-OAEP-SHA256 | 2048+ bit |
| PGP | DSA + RSA subkey | ProtonMail go-crypto |
| HMAC | SHA-256 / SHA-512 | Constant-time verify |

## Security Considerations

1. **LTHN hash is NOT for passwords** — deterministic, no random salt. Use `HashPassword()` (Argon2id) instead.
2. **Sessions default to in-memory** — use `WithSessionStore(NewSQLiteSessionStore(path))` for persistence across restarts.
3. **PGP output is armored** — ~33% Base64 overhead. Consider compression for large payloads.
4. **Policy engine returns decisions but doesn't enforce approval workflow** — higher-level layer needed.
5. **Challenge nonces are 32 bytes** — 256-bit, cryptographically random.

## Coding Standards

- **UK English**: colour, organisation, centre
- **Tests**: testify assert/require, `_Good`/`_Bad`/`_Ugly` naming convention
- **Conventional commits**: `feat(auth):`, `fix(crypt):`, `refactor(trust):`
- **Co-Author**: `Co-Authored-By: Virgil <virgil@lethean.io>`
- **Licence**: EUPL-1.2
- **Imports**: stdlib → forge.lthn.ai → third-party, each group separated by blank line

## Forge

- **Repo**: `forge.lthn.ai/core/go-crypt`
- **Push via SSH**: `git push forge main` (remote: `ssh://git@forge.lthn.ai:2223/core/go-crypt.git`)

## Task Queue

See `TODO.md` for prioritised work. See `FINDINGS.md` for research notes.
