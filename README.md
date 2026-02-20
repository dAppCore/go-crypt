# go-crypt

Cryptographic primitives, authentication, and trust policy engine for the Lethean agent platform. Provides symmetric encryption (ChaCha20-Poly1305 and AES-256-GCM with Argon2id KDF), OpenPGP challenge-response authentication with online and air-gapped courier modes, Argon2id password hashing, RSA-OAEP key generation, RFC-0004 deterministic content hashing, and a three-tier agent trust policy engine with an audit log and approval queue.

**Module**: `forge.lthn.ai/core/go-crypt`
**Licence**: EUPL-1.2
**Language**: Go 1.25

## Quick Start

```go
import (
    "forge.lthn.ai/core/go-crypt/crypt"
    "forge.lthn.ai/core/go-crypt/auth"
    "forge.lthn.ai/core/go-crypt/trust"
)

// Encrypt with ChaCha20-Poly1305 + Argon2id KDF
ciphertext, err := crypt.Encrypt(plaintext, passphrase)

// OpenPGP authentication
a := auth.New(medium, auth.WithSessionStore(auth.NewSQLiteSessionStore(dbPath)))
session, err := a.Login(userID, password)

// Trust policy evaluation
engine := trust.NewPolicyEngine(registry)
decision := engine.Evaluate("Charon", "repo.push", "core/go-crypt")
```

## Documentation

- [Architecture](docs/architecture.md) — crypt primitives, auth protocol, trust tiers, policy engine
- [Development Guide](docs/development.md) — building, testing, security standards
- [Project History](docs/history.md) — completed phases and known limitations

## Build & Test

```bash
go test ./...
go test -race ./...
go build ./...
```

## Licence

European Union Public Licence 1.2 — see [LICENCE](LICENCE) for details.
