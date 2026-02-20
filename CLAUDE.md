# CLAUDE.md — go-crypt

You are a dedicated domain expert for `forge.lthn.ai/core/go-crypt`. Virgil (in
core/go) orchestrates your work. Pick up tasks in phase order, mark `[x]` when
done, commit and push.

## What This Package Does

Cryptographic primitives, authentication, and trust policy engine for the
Lethean agent platform. Provides:

- Symmetric encryption — ChaCha20-Poly1305 and AES-256-GCM with Argon2id KDF
- OpenPGP authentication — challenge-response (online + air-gapped courier mode)
- Password hashing — Argon2id (primary) + Bcrypt (fallback)
- Trust policy engine — 3-tier agent access control with capability evaluation
- RSA — OAEP-SHA256 key generation and encryption (2048+ bit)
- LTHN hash — RFC-0004 quasi-salted deterministic hash (content IDs, NOT passwords)

For architecture details see `docs/architecture.md`. For history and findings
see `docs/history.md`.

## Commands

```bash
go test ./...                    # Run all tests
go test -race ./...              # Race detector (required before committing)
go test -v -run TestName ./...   # Single test
go vet ./...                     # Static analysis (must be clean)
```

## Local Dependencies

| Module | Local Path | Notes |
|--------|-----------|-------|
| `forge.lthn.ai/core/go` | `../go` | Framework (core.E, core.Crypt, io.Medium) |
| `forge.lthn.ai/core/go-store` | `../go-store` | SQLite KV store (session persistence) |

Do not change the replace directive paths. Use a `go.work` for local resolution
if working outside the full monorepo.

## Coding Standards

- **UK English**: colour, organisation, centre, artefact, licence, serialise
- **Tests**: testify assert/require, `_Good`/`_Bad`/`_Ugly` naming convention
- **Concurrency tests**: 10 goroutines via WaitGroup; must pass `-race`
- **Imports**: stdlib → forge.lthn.ai → third-party, separated by blank lines
- **Errors**: use `core.E("package.Function", "lowercase message", err)`; never
  include secrets in error strings
- **Randomness**: `crypto/rand` only; never `math/rand`
- **Conventional commits**: `feat(auth):`, `fix(crypt):`, `refactor(trust):`
- **Co-Author**: `Co-Authored-By: Virgil <virgil@lethean.io>`
- **Licence**: EUPL-1.2

## Forge

- **Repo**: `forge.lthn.ai/core/go-crypt`
- **Push via SSH**: `git push forge main`
  (remote: `ssh://git@forge.lthn.ai:2223/core/go-crypt.git`)
