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
