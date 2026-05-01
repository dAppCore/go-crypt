# go-crypt Agent Notes

This repository follows the core/go v0.9.0 consumer layout.

- Keep Go source under `go/`.
- Keep dependency source under `external/` submodules.
- Do not edit `.core/` runtime configuration.
- Three independent top-level packages: `crypt/` (symmetric/asymmetric primitives), `auth/` (OpenPGP + password authentication), `trust/` (3-tier capability access control).
- Only `crypt/openpgp/` integrates with the Core IPC system (`core.Crypt` interface).
- Run the v0.9.0 audit from the repository root before finishing.
