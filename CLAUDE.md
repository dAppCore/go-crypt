# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

You are a dedicated domain expert for `dappco.re/go/core/crypt`. Virgil (in
core/go) orchestrates your work. Pick up tasks in phase order, mark `[x]` when
done, commit and push.

## What This Package Does

Cryptographic primitives, authentication, and trust policy engine for the
Lethean agent platform. Three independent top-level packages:

- **`crypt/`** — Symmetric encryption (ChaCha20-Poly1305, AES-256-GCM), Argon2id
  KDF, password hashing, HMAC, checksums. Sub-packages: `chachapoly/`, `lthn/`,
  `pgp/`, `rsa/`, `openpgp/`.
- **`auth/`** — OpenPGP challenge-response authentication (online + air-gapped
  courier mode), password-based login with Argon2id→LTHN migration, session
  management via `SessionStore` interface, key rotation and revocation.
- **`trust/`** — 3-tier agent access control (`Registry`, `PolicyEngine`,
  `ApprovalQueue`, `AuditLog`), capability evaluation with repo scope matching.

Each package can be imported independently. Only `crypt/openpgp/` integrates
with the Core framework's IPC system (`core.Crypt` interface).

For architecture details see `docs/architecture.md`. For history and findings
see `docs/history.md`.

## Commands

```bash
go test ./...                        # Run all tests
go test -race ./...                  # Race detector (required before committing)
go test -v -run TestName ./...       # Single test
go test ./auth/...                   # Single package
go vet ./...                         # Static analysis (must be clean)
go test -bench=. -benchmem ./crypt/... # Benchmarks
```

## Local Dependencies

All `dappco.re/go/core/*` and remaining `forge.lthn.ai/core/*` modules are resolved through the Go workspace
(`~/Code/go.work`). Do not add replace directives to `go.mod` — use the
workspace file instead.

| Module | Local Path | Purpose |
|--------|-----------|---------|
| `dappco.re/go/core` | `../go` | Framework: `core.Crypt` interface, `io.Medium` |
| `dappco.re/go/core/log` | `../go-log` | `coreerr.E()` contextual error wrapping |
| `dappco.re/go/core/io` | `../go-io` | `io.Medium` storage abstraction |
| `dappco.re/go/core/store` | `../go-store` | SQLite KV store (session persistence) |
| `forge.lthn.ai/core/cli` | `../cli` | CLI framework for `cmd/crypt` commands |

No C toolchain or CGo required — all crypto uses pure Go implementations.

## Coding Standards

- **UK English**: colour, organisation, centre, artefact, licence, serialise
- **Tests**: testify assert/require, `_Good`/`_Bad`/`_Ugly` naming convention
- **Concurrency tests**: 10 goroutines via WaitGroup; must pass `-race`
- **Imports**: stdlib → dappco.re/forge.lthn.ai → third-party, separated by blank lines
- **Errors**: use `coreerr.E("package.Function", "lowercase message", err)` (imported
  as `coreerr "dappco.re/go/core/log"`); never include secrets in error strings
- **Randomness**: `crypto/rand` only; never `math/rand`
- **Conventional commits**: `feat(auth):`, `fix(crypt):`, `refactor(trust):`
  Scopes match package names: `auth`, `crypt`, `trust`, `pgp`, `lthn`, `rsa`,
  `openpgp`, `chachapoly`
- **Co-Author**: `Co-Authored-By: Virgil <virgil@lethean.io>`
- **Licence**: EUPL-1.2

## Forge

- **Repo**: `dappco.re/go/core/crypt`
- **Push via SSH**: `git push forge main`
  (remote: `ssh://git@forge.lthn.ai:2223/core/go-crypt.git`)
