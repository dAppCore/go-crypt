---
title: Development Guide
description: How to build, test, and contribute to go-crypt.
---

# Development Guide

## Prerequisites

- **Go 1.26** or later (the module declares `go 1.26.0`).
- A Go workspace (`go.work`) that resolves the local dependencies:
  `forge.lthn.ai/core/go`, `forge.lthn.ai/core/go-store`,
  `forge.lthn.ai/core/go-io`, `forge.lthn.ai/core/go-log`, and
  `forge.lthn.ai/core/cli`. If you are working outside the full monorepo,
  create a `go.work` at the parent directory pointing to your local
  checkouts.
- No C toolchain, CGo, or system libraries are required. All cryptographic
  operations use pure Go implementations.

## Build and Test

```bash
# Run all tests
go test ./...

# Run with race detector (required before committing)
go test -race ./...

# Run a single test by name
go test -v -run TestName ./...

# Run tests in a specific package
go test ./auth/...
go test ./crypt/...
go test ./trust/...

# Static analysis (must be clean before committing)
go vet ./...

# Run benchmarks
go test -bench=. -benchmem ./crypt/...
go test -bench=. -benchmem ./trust/...

# Extended benchmark run
go test -bench=. -benchmem -benchtime=3s ./crypt/...
```

If using the `core` CLI:

```bash
core go test
core go test --run TestName
core go qa              # fmt + vet + lint + test
core go qa full         # + race, vuln, security
```

## Repository Layout

```
go-crypt/
├── auth/               Authentication: Authenticator, sessions, key management
├── cmd/
│   ├── crypt/          CLI commands: encrypt, decrypt, hash, keygen, checksum
│   └── testcmd/        Test runner commands
├── crypt/              Symmetric encryption, hashing, key derivation
│   ├── chachapoly/     Standalone ChaCha20-Poly1305 AEAD
│   ├── lthn/           RFC-0004 quasi-salted deterministic hash
│   ├── openpgp/        core.Crypt service wrapper
│   ├── pgp/            OpenPGP primitives
│   └── rsa/            RSA-OAEP-SHA256
├── docs/               Documentation
├── trust/              Agent trust model, policy engine, audit log
├── go.mod
└── go.sum
```

## Test Patterns

Tests use `github.com/stretchr/testify` (`assert` and `require`). The
naming convention uses three suffixes to categorise test intent:

| Suffix | Purpose |
|--------|---------|
| `_Good` | Happy path -- expected success |
| `_Bad` | Expected failure -- invalid input, wrong credentials, not-found errors |
| `_Ugly` | Edge cases -- panics, zero values, empty inputs, extreme lengths |

Example:

```go
func TestLogin_Good(t *testing.T) {
    // Register a user, log in with correct password, verify session
}

func TestLogin_Bad(t *testing.T) {
    // Attempt login with wrong password, verify rejection
}

func TestLogin_Ugly(t *testing.T) {
    // Empty password, very long input, Unicode edge cases
}
```

### Concurrency Tests

Concurrent tests spawn 10 goroutines via a `sync.WaitGroup` and use
`t.Parallel()`. The race detector (`go test -race`) must pass for all
concurrent tests. Examples include concurrent session creation, concurrent
registry access, and concurrent policy evaluation.

### Benchmarks

Benchmarks live in `bench_test.go` files alongside the packages they cover:

- `crypt/bench_test.go`: Argon2id derivation, ChaCha20 and AES-GCM at
  1KB and 1MB payloads, HMAC-SHA256, HMAC verification.
- `trust/bench_test.go`: policy evaluation with 100 agents, registry
  get, registry register.

**Note**: The Argon2id KDF is intentionally slow (~200ms on typical
hardware). This is a security property, not a performance defect. Do not
optimise KDF parameters without understanding the security implications.

## Adding a New Cryptographic Primitive

1. Add the implementation in the appropriate sub-package under `crypt/`.
2. Write tests covering `_Good`, `_Bad`, and `_Ugly` cases.
3. Add a benchmark if the function is called on hot paths.
4. Update `docs/architecture.md` with the algorithm reference entry.
5. Run `go vet ./...` and `go test -race ./...` before committing.

## Adding a New Trust Capability

1. Add the `Capability` constant in `trust/trust.go`.
2. If the capability is repository-scoped, update `isRepoScoped()` in
   `trust/policy.go`.
3. Update the default policies in `loadDefaults()` in `trust/policy.go`.
4. Add tests covering all three tiers.
5. Update the capability table in `docs/architecture.md`.

## Coding Standards

### Language

UK English throughout: _colour_, _organisation_, _centre_, _artefact_,
_licence_ (noun), _license_ (verb), _behaviour_, _initialise_, _serialise_.

### Go Style

- Every exported function and type must have a doc comment.
- Error strings are lowercase and do not end with a full stop, per Go
  convention.
- Use the `core.E(op, msg, err)` helper for contextual error wrapping:
  `op` is `"package.Function"`, `msg` is a brief lowercase description.
- Import groups, separated by blank lines: stdlib, then `forge.lthn.ai/core`,
  then third-party.
- Avoid `any` except at interface boundaries. Prefer explicit type
  assertions.

### Cryptographic Safety

- All randomness from `crypto/rand`. Never use `math/rand` for
  cryptographic purposes.
- Use `crypto/subtle.ConstantTimeCompare` for any comparison of secret
  material (MACs, password hashes, session tokens).
- Never log or return secrets in error messages. Keep error strings
  generic: `"invalid password"`, `"session not found"`, `"failed to
  decrypt"`.

### Licence

All files are licenced under EUPL-1.2. Do not add files under a different
licence.

## Commit Convention

Commits follow the Conventional Commits specification:

```
type(scope): short imperative description

Optional body explaining motivation and context.

Co-Authored-By: Virgil <virgil@lethean.io>
```

**Types**: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.

**Scopes** match package names: `auth`, `crypt`, `trust`, `pgp`, `lthn`,
`rsa`, `openpgp`, `chachapoly`.

Examples:

```
feat(auth): add SQLite session store for crash recovery
fix(trust): reject empty ScopedRepos as no-access for Tier 2
test(crypt): add benchmark suite for Argon2 and ChaCha20
docs(trust): document approval queue workflow
```

## Pushing to Forge

The canonical remote is `forge.lthn.ai`. Push via SSH only:

```bash
git push forge main
# remote: ssh://git@forge.lthn.ai:2223/core/go-crypt.git
```

HTTPS authentication is not configured for this repository.

## Local Dependencies

The `go.mod` depends on several `forge.lthn.ai/core/*` modules. These are
resolved through the Go workspace (`~/Code/go.work`). Do not modify the
replace directives in `go.mod` directly -- use the workspace file instead.

| Module | Local Path | Purpose |
|--------|-----------|---------|
| `forge.lthn.ai/core/go` | `../go` | Framework: `core.Crypt` interface, `io.Medium` |
| `forge.lthn.ai/core/go-store` | `../go-store` | SQLite KV store for session persistence |
| `forge.lthn.ai/core/go-io` | `../go-io` | `io.Medium` storage abstraction |
| `forge.lthn.ai/core/go-log` | `../go-log` | `core.E()` contextual error wrapping |
| `forge.lthn.ai/core/cli` | `../cli` | CLI framework for `cmd/crypt` commands |

## Known Limitations

For a full list of known limitations and open security findings, see
[history.md](history.md).

Key items:

- **Dual ChaCha20 implementations**: `crypt/symmetric.go` and
  `crypt/chachapoly/` are nearly identical. Consolidation would reduce
  duplication but requires updating all importers.
- **Hardware key interface**: contract-only, no concrete implementations.
- **Session cleanup logging**: uses `fmt.Printf` rather than a structured
  logger. Callers needing structured logs should wrap the cleanup goroutine.
- **Rate limiting**: the `Agent.RateLimit` field is stored but never
  enforced. Enforcement belongs in a higher-level middleware layer.
