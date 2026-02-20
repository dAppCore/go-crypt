# Development Guide — go-crypt

## Prerequisites

- Go 1.25 or later (the module declares `go 1.25.5`).
- A Go workspace (`go.work`) that resolves the local replace directives for
  `forge.lthn.ai/core/go` (at `../go`) and `forge.lthn.ai/core/go-store`
  (at `../go-store`). If you are working outside the full monorepo, edit
  `go.mod` replace directives to point to your local checkouts.
- No C toolchain, CGo, or system libraries are required.

## Build and Test Commands

```bash
# Run all tests
go test ./...

# Run with race detector (always use before committing)
go test -race ./...

# Run a single test by name
go test -v -run TestName ./...

# Run tests in a specific package
go test ./auth/...
go test ./crypt/...
go test ./trust/...

# Static analysis
go vet ./...

# Run benchmarks
go test -bench=. -benchmem ./crypt/...
go test -bench=. -benchmem ./trust/...
```

There is no build step — this is a library module with no binaries. The
`go vet ./...` check must pass cleanly before any commit.

## Repository Layout

```
go-crypt/
├── auth/               Authentication package
├── crypt/              Cryptographic utilities
│   ├── chachapoly/     Standalone ChaCha20-Poly1305 sub-package
│   ├── lthn/           RFC-0004 quasi-salted hash
│   ├── openpgp/        Service wrapper (core.Crypt interface)
│   ├── pgp/            OpenPGP primitives
│   └── rsa/            RSA OAEP-SHA256
├── docs/               Architecture, development, and history docs
├── trust/              Agent trust model and policy engine
├── go.mod
└── go.sum
```

## Test Patterns

Tests use the `github.com/stretchr/testify` library (`assert` and `require`).
The naming convention follows three suffixes:

| Suffix | Purpose |
|--------|---------|
| `_Good` | Happy path — expected success |
| `_Bad` | Expected failure — invalid input, wrong credentials, not-found errors |
| `_Ugly` | Edge cases — panics, zero values, empty inputs, extreme lengths |

Example:

```go
func TestLogin_Good(t *testing.T) { ... }
func TestLogin_Bad(t *testing.T) { ... }
func TestLogin_Ugly(t *testing.T) { ... }
```

Concurrency tests use `t.Parallel()` and typically spawn 10 goroutines via a
`sync.WaitGroup`. The race detector (`-race`) must pass for all concurrent tests.

## Benchmark Structure

Benchmarks live in `bench_test.go` files alongside the packages they cover.
Benchmark names follow the `BenchmarkFuncName_Context` pattern:

```go
func BenchmarkArgon2Derive(b *testing.B) { ... }
func BenchmarkChaCha20_1KB(b *testing.B) { ... }
func BenchmarkChaCha20_1MB(b *testing.B) { ... }
```

Run benchmarks with:

```bash
go test -bench=. -benchmem -benchtime=3s ./crypt/...
```

Do not optimise without measuring first. The Argon2id KDF is intentionally slow
(~200ms on typical hardware) — this is a security property, not a defect.

## Adding a New Cryptographic Primitive

1. Add the implementation in the appropriate sub-package.
2. Write tests covering `_Good`, `_Bad`, and `_Ugly` cases.
3. Add a benchmark if the function is called on hot paths.
4. Update `docs/architecture.md` with the algorithm reference entry.
5. Run `go vet ./...` and `go test -race ./...` before committing.

## Adding a New Trust Capability

1. Add the `Capability` constant in `trust/trust.go`.
2. Update `isRepoScoped()` in `trust/policy.go` if the capability is
   repository-scoped.
3. Update the default policies in `loadDefaults()` in `trust/policy.go`.
4. Add tests covering all three tiers.
5. Update the capability table in `docs/architecture.md`.

## Coding Standards

### Language

UK English throughout: _colour_, _organisation_, _centre_, _artefact_,
_licence_ (noun), _license_ (verb), _behaviour_, _initialise_, _serialise_.

### Go Style

- `declare(strict_types=1)` is a PHP convention; Go has no equivalent. Use
  explicit type assertions and avoid `any` except at interface boundaries.
- Every exported function and type must have a doc comment.
- Error strings are lowercase and do not end with a full stop, per Go convention.
- Use the `core.E(op, msg, err)` helper from `forge.lthn.ai/core/go` for
  contextual error wrapping: `op` is `"package.Function"`, `msg` is a brief
  lowercase description.
- Import groups: stdlib → `forge.lthn.ai/core` → third-party. Separate each
  group with a blank line.

### Cryptography

- All randomness from `crypto/rand`. Never use `math/rand` for cryptographic
  purposes.
- Use `crypto/subtle.ConstantTimeCompare` for any comparison of secret material
  (MACs, hashes). The one exception is `lthn.Verify`, which compares content
  identifiers (not secrets) and documents this explicitly.
- Never log or return secrets in error messages. Error strings should be generic:
  `"invalid password"`, `"session not found"`, `"failed to decrypt"`.

### Licence

All files are licenced under EUPL-1.2. Do not add files under a different licence.

## Commit Convention

Commits follow the Conventional Commits specification:

```
type(scope): short imperative description

Optional body explaining motivation and context.

Co-Authored-By: Virgil <virgil@lethean.io>
```

Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`.

Scopes match package names: `auth`, `crypt`, `trust`, `pgp`, `lthn`, `rsa`,
`openpgp`, `chachapoly`.

Examples:

```
feat(auth): add SQLite session store for crash recovery
fix(trust): reject empty ScopedRepos as no-access for Tier 2
test(crypt): add benchmark suite for Argon2 and ChaCha20
```

## Forge Push

The canonical remote is `forge.lthn.ai`. Push via SSH only; HTTPS authentication
is not configured:

```bash
git push forge main
# remote: ssh://git@forge.lthn.ai:2223/core/go-crypt.git
```

## Local Replace Directives

The `go.mod` contains:

```
replace (
    forge.lthn.ai/core/go => ../go
    forge.lthn.ai/core/go-store => ../go-store
)
```

Do not modify these paths. If you need to work with a different local checkout,
use a Go workspace (`go.work`) at the parent directory level rather than editing
the replace directives directly.
