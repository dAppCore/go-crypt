# Upgrade Plan: v0.8.0 AX Compliance

Scope: planning only. This document identifies the repo changes required for AX v0.8.0 compliance without changing package code yet.

Breaking-change risk: medium. This module is consumed by `core`, `go-blockchain`, and `LEM`, so any public API edits made during compliance work should be reviewed as a consumer-facing change even if the primary AX items are mechanical.

## Current Audit Summary

- Banned imports: 52 hits across production and test code.
- Test naming violations: 292 `Test...` functions do not follow `TestFile_Function_{Good,Bad,Ugly}`.
- Exported API usage-example gaps: 162 exported declarations in non-test files do not include a usage/example-oriented doc comment.

## Execution Order

1. Fix production banned imports first to reduce AX failures without changing public behaviour.
2. Rename tests package-by-package, starting with the largest files, and rerun targeted `go test ./...`.
3. Add usage/example comments to exported API surfaces, starting with the packages most likely to be imported by consumers: `auth`, `crypt`, `trust`.
4. Run the full validation flow: `go build ./...`, `go vet ./...`, `go test ./... -count=1 -timeout 120s`, `go test -cover ./...`, `go mod tidy`.
5. Review downstream consumers for naming-only vs behavioural risk before releasing v0.8.0.

## 1. Remove Banned Imports

Production code should be prioritised before test helpers.

### Production files

- `auth/auth.go`: replace banned imports at `auth/auth.go:32`, `auth/auth.go:33`, `auth/auth.go:34`.
- `auth/session_store_sqlite.go`: replace banned imports at `auth/session_store_sqlite.go:4`, `auth/session_store_sqlite.go:5`.
- `cmd/crypt/cmd_checksum.go`: replace banned imports at `cmd/crypt/cmd_checksum.go:4`, `cmd/crypt/cmd_checksum.go:5`.
- `cmd/crypt/cmd_encrypt.go`: replace banned imports at `cmd/crypt/cmd_encrypt.go:4`, `cmd/crypt/cmd_encrypt.go:5`.
- `cmd/crypt/cmd_hash.go`: replace banned import at `cmd/crypt/cmd_hash.go:4`.
- `cmd/crypt/cmd_keygen.go`: replace banned import at `cmd/crypt/cmd_keygen.go:7`.
- `cmd/testcmd/cmd_output.go`: replace banned imports at `cmd/testcmd/cmd_output.go:6`, `cmd/testcmd/cmd_output.go:7`, `cmd/testcmd/cmd_output.go:11`.
- `cmd/testcmd/cmd_runner.go`: replace banned imports at `cmd/testcmd/cmd_runner.go:5`, `cmd/testcmd/cmd_runner.go:7`, `cmd/testcmd/cmd_runner.go:8`, `cmd/testcmd/cmd_runner.go:10`.
- `crypt/chachapoly/chachapoly.go`: replace banned import at `crypt/chachapoly/chachapoly.go:5`.
- `crypt/checksum.go`: replace banned import at `crypt/checksum.go:8`.
- `crypt/hash.go`: replace banned imports at `crypt/hash.go:6`, `crypt/hash.go:7`.
- `crypt/openpgp/service.go`: replace banned import at `crypt/openpgp/service.go:7`.
- `crypt/rsa/rsa.go`: replace banned import at `crypt/rsa/rsa.go:9`.
- `trust/approval.go`: replace banned import at `trust/approval.go:4`.
- `trust/audit.go`: replace banned import at `trust/audit.go:4`.
- `trust/config.go`: replace banned imports at `trust/config.go:4`, `trust/config.go:5`, `trust/config.go:7`.
- `trust/policy.go`: replace banned imports at `trust/policy.go:4`, `trust/policy.go:6`.
- `trust/trust.go`: replace banned import at `trust/trust.go:14`.

### Test files

- `auth/auth_test.go`: banned imports at `auth/auth_test.go:4`, `auth/auth_test.go:5`, `auth/auth_test.go:6`.
- `auth/session_store_test.go`: banned imports at `auth/session_store_test.go:5`, `auth/session_store_test.go:6`, `auth/session_store_test.go:7`.
- `crypt/chachapoly/chachapoly_test.go`: banned import at `crypt/chachapoly/chachapoly_test.go:5`.
- `crypt/checksum_test.go`: banned imports at `crypt/checksum_test.go:4`, `crypt/checksum_test.go:5`.
- `crypt/rsa/rsa_test.go`: banned import at `crypt/rsa/rsa_test.go:9`.
- `trust/approval_test.go`: banned import at `trust/approval_test.go:4`.
- `trust/audit_test.go`: banned imports at `trust/audit_test.go:5`, `trust/audit_test.go:6`, `trust/audit_test.go:8`.
- `trust/bench_test.go`: banned import at `trust/bench_test.go:4`.
- `trust/config_test.go`: banned imports at `trust/config_test.go:5`, `trust/config_test.go:6`, `trust/config_test.go:7`, `trust/config_test.go:8`.
- `trust/trust_test.go`: banned import at `trust/trust_test.go:4`.

Plan notes:

- Prefer package-local replacements already used elsewhere in the repo rather than introducing new compatibility shims.
- `cmd/testcmd/cmd_runner.go:8` is the only `os/exec` hit and may need the largest redesign if AX forbids subprocess execution outright.
- `encoding/json` use is concentrated in `auth` and `trust`; validate AX-approved serialisation alternatives before changing wire formats consumed by downstream modules.

## 2. Rename Tests To `TestFile_Function_{Good,Bad,Ugly}`

Every audited `Test...` function currently fails the file-prefix requirement. The work is mechanical but broad, so do it file-by-file to keep diffs reviewable.

### Highest-volume files first

- `auth/auth_test.go`: 55 renames, starting at `auth/auth_test.go:28`.
- `trust/policy_test.go`: 38 renames, starting at `trust/policy_test.go:32`.
- `trust/trust_test.go`: 26 renames, starting at `trust/trust_test.go:15`.
- `trust/approval_test.go`: 23 renames, starting at `trust/approval_test.go:14`.
- `trust/scope_test.go`: 23 renames, starting at `trust/scope_test.go:12`.
- `trust/config_test.go`: 20 renames, starting at `trust/config_test.go:37`.
- `auth/session_store_test.go`: 19 renames, starting at `auth/session_store_test.go:21`.
- `trust/audit_test.go`: 17 renames, starting at `trust/audit_test.go:18`.

### Remaining files

- `crypt/pgp/pgp_test.go`: 12 renames, starting at `crypt/pgp/pgp_test.go:10`.
- `crypt/chachapoly/chachapoly_test.go`: 9 renames, starting at `crypt/chachapoly/chachapoly_test.go:18`.
- `crypt/symmetric_test.go`: 8 renames, starting at `crypt/symmetric_test.go:10`.
- `crypt/checksum_test.go`: 7 renames, starting at `crypt/checksum_test.go:12`.
- `crypt/crypt_test.go`: 7 renames, starting at `crypt/crypt_test.go:11`.
- `crypt/lthn/lthn_test.go`: 7 renames, starting at `crypt/lthn/lthn_test.go:10`.
- `crypt/kdf_test.go`: 6 renames, starting at `crypt/kdf_test.go:9`.
- `cmd/testcmd/output_test.go`: 4 renames, starting at `cmd/testcmd/output_test.go:9`.
- `crypt/hash_test.go`: 3 renames, starting at `crypt/hash_test.go:10`.
- `crypt/hmac_test.go`: 3 renames, starting at `crypt/hmac_test.go:11`.
- `crypt/rsa/rsa_test.go`: 3 renames, starting at `crypt/rsa/rsa_test.go:22`.
- `crypt/openpgp/service_test.go`: 2 renames, starting at `crypt/openpgp/service_test.go:12`.

Plan notes:

- Apply the file stem as the prefix. Examples: `approval_test.go` -> `TestApproval_...`, `policy_test.go` -> `TestPolicy_...`, `session_store_test.go` -> `TestSessionStore_...`.
- Preserve existing subcase suffixes after `Good`, `Bad`, or `Ugly` where they add meaning.
- Renames should not change behaviour, but they can break editor tooling, test filters, and CI allowlists that depend on old names.

## 3. Add Usage-Example Comments To Exported API

The package has normal doc comments in many places, but the audit found no usage/example-oriented export comments matching AX expectations. This affects all major public surfaces.

### `auth` package

- `auth/auth.go`: 26 exported declarations at `auth/auth.go:47`, `auth/auth.go:48`, `auth/auth.go:60`, `auth/auth.go:70`, `auth/auth.go:77`, `auth/auth.go:85`, `auth/auth.go:92`, `auth/auth.go:95`, `auth/auth.go:102`, `auth/auth.go:110`, `auth/auth.go:125`, `auth/auth.go:138`, `auth/auth.go:164`, `auth/auth.go:241`, `auth/auth.go:283`, `auth/auth.go:317`, `auth/auth.go:334`, `auth/auth.go:355`, `auth/auth.go:367`, `auth/auth.go:407`, `auth/auth.go:459`, `auth/auth.go:540`, `auth/auth.go:576`, `auth/auth.go:600`, `auth/auth.go:623`, `auth/auth.go:696`.
- `auth/hardware.go`: 2 exported declarations at `auth/hardware.go:20`, `auth/hardware.go:47`.
- `auth/session_store.go`: 9 exported declarations at `auth/session_store.go:12`, `auth/session_store.go:15`, `auth/session_store.go:24`, `auth/session_store.go:30`, `auth/session_store.go:37`, `auth/session_store.go:52`, `auth/session_store.go:63`, `auth/session_store.go:76`, `auth/session_store.go:87`.
- `auth/session_store_sqlite.go`: 8 exported declarations at `auth/session_store_sqlite.go:16`, `auth/session_store_sqlite.go:23`, `auth/session_store_sqlite.go:32`, `auth/session_store_sqlite.go:52`, `auth/session_store_sqlite.go:64`, `auth/session_store_sqlite.go:80`, `auth/session_store_sqlite.go:104`, `auth/session_store_sqlite.go:131`.

### `crypt` package family

- `crypt/chachapoly/chachapoly.go`: 2 exported declarations at `crypt/chachapoly/chachapoly.go:14`, `crypt/chachapoly/chachapoly.go:29`.
- `crypt/checksum.go`: 4 exported declarations at `crypt/checksum.go:14`, `crypt/checksum.go:30`, `crypt/checksum.go:46`, `crypt/checksum.go:52`.
- `crypt/crypt.go`: 4 exported declarations at `crypt/crypt.go:10`, `crypt/crypt.go:32`, `crypt/crypt.go:53`, `crypt/crypt.go:74`.
- `crypt/hash.go`: 4 exported declarations at `crypt/hash.go:17`, `crypt/hash.go:37`, `crypt/hash.go:72`, `crypt/hash.go:81`.
- `crypt/hmac.go`: 3 exported declarations at `crypt/hmac.go:11`, `crypt/hmac.go:18`, `crypt/hmac.go:26`.
- `crypt/kdf.go`: 3 exported declarations at `crypt/kdf.go:28`, `crypt/kdf.go:34`, `crypt/kdf.go:45`.
- `crypt/lthn/lthn.go`: 4 exported declarations at `crypt/lthn/lthn.go:45`, `crypt/lthn/lthn.go:50`, `crypt/lthn/lthn.go:64`, `crypt/lthn/lthn.go:92`.
- `crypt/openpgp/service.go`: 6 exported declarations at `crypt/openpgp/service.go:18`, `crypt/openpgp/service.go:23`, `crypt/openpgp/service.go:29`, `crypt/openpgp/service.go:104`, `crypt/openpgp/service.go:139`, `crypt/openpgp/service.go:177`.
- `crypt/pgp/pgp.go`: 6 exported declarations at `crypt/pgp/pgp.go:19`, `crypt/pgp/pgp.go:27`, `crypt/pgp/pgp.go:119`, `crypt/pgp/pgp.go:152`, `crypt/pgp/pgp.go:196`, `crypt/pgp/pgp.go:227`.
- `crypt/rsa/rsa.go`: 5 exported declarations at `crypt/rsa/rsa.go:15`, `crypt/rsa/rsa.go:18`, `crypt/rsa/rsa.go:23`, `crypt/rsa/rsa.go:53`, `crypt/rsa/rsa.go:80`.
- `crypt/symmetric.go`: 4 exported declarations at `crypt/symmetric.go:16`, `crypt/symmetric.go:33`, `crypt/symmetric.go:56`, `crypt/symmetric.go:78`.

### `trust` package

- `trust/approval.go`: 15 exported declarations at `trust/approval.go:13`, `trust/approval.go:17`, `trust/approval.go:19`, `trust/approval.go:21`, `trust/approval.go:25`, `trust/approval.go:39`, `trust/approval.go:61`, `trust/approval.go:68`, `trust/approval.go:76`, `trust/approval.go:104`, `trust/approval.go:125`, `trust/approval.go:145`, `trust/approval.go:159`, `trust/approval.go:173`, `trust/approval.go:189`.
- `trust/audit.go`: 11 exported declarations at `trust/audit.go:14`, `trust/audit.go:30`, `trust/audit.go:35`, `trust/audit.go:54`, `trust/audit.go:62`, `trust/audit.go:69`, `trust/audit.go:99`, `trust/audit.go:109`, `trust/audit.go:123`, `trust/audit.go:130`, `trust/audit.go:144`.
- `trust/config.go`: 7 exported declarations at `trust/config.go:13`, `trust/config.go:21`, `trust/config.go:26`, `trust/config.go:36`, `trust/config.go:70`, `trust/config.go:84`, `trust/config.go:94`.
- `trust/policy.go`: 12 exported declarations at `trust/policy.go:12`, `trust/policy.go:24`, `trust/policy.go:30`, `trust/policy.go:34`, `trust/policy.go:36`, `trust/policy.go:38`, `trust/policy.go:42`, `trust/policy.go:56`, `trust/policy.go:64`, `trust/policy.go:76`, `trust/policy.go:149`, `trust/policy.go:158`.
- `trust/trust.go`: 25 exported declarations at `trust/trust.go:23`, `trust/trust.go:27`, `trust/trust.go:29`, `trust/trust.go:31`, `trust/trust.go:35`, `trust/trust.go:49`, `trust/trust.go:54`, `trust/trust.go:57`, `trust/trust.go:58`, `trust/trust.go:59`, `trust/trust.go:60`, `trust/trust.go:61`, `trust/trust.go:62`, `trust/trust.go:63`, `trust/trust.go:64`, `trust/trust.go:65`, `trust/trust.go:69`, `trust/trust.go:86`, `trust/trust.go:92`, `trust/trust.go:100`, `trust/trust.go:121`, `trust/trust.go:128`, `trust/trust.go:139`, `trust/trust.go:150`, `trust/trust.go:163`.

### Command entrypoints

- `cmd/crypt/cmd.go`: exported declaration at `cmd/crypt/cmd.go:10`.
- `cmd/testcmd/cmd_main.go`: exported declaration at `cmd/testcmd/cmd_main.go:59`.

Plan notes:

- Keep comments example-oriented and consumer-safe. Public comments should explain the happy-path call pattern without embedding secrets or unstable implementation details.
- Prioritise constructor and entrypoint comments first: `auth.New`, `trust.NewRegistry`, `trust.NewPolicyEngine`, `trust.NewApprovalQueue`, `trust.NewAuditLog`, `crypt/openpgp.New`, `crypt/rsa.NewService`, and the command registration functions.
- If AX requires literal `Usage:` blocks, standardise that wording repo-wide before editing all 162 declarations.

## 4. Validation And Release Checks

- Run the required flow after each migration stage, not only at the end, so failures stay attributable to one category of change.
- Add a final review for consumer impact before tagging `v0.8.0`, especially if banned-import replacements force API or behaviour adjustments in `auth`, `trust/config`, or CLI codepaths.
- Commit the compliance work in small conventional-commit slices where practical. If the migration is done in one batch, use a non-breaking conventional commit scope that matches the touched package set.
