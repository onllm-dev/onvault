# CLAUDE.md — onvault

## Project Overview

**onvault** is a seamless file encryption & per-process access control system for macOS. It protects sensitive directories (`~/.ssh`, `~/.aws`, `~/.kube`, etc.) from supply chain attacks by encrypting files at rest and only allowing verified, code-signed binaries to access them.

- **Language:** Pure C + Objective-C (for macOS frameworks)
- **License:** GPL-3.0
- **Platform:** macOS 15 Sequoia+ (Apple Silicon)
- **Repo:** github.com/onllm-dev/onvault
- **Brand family:** on- prefix (onui, onwatch, ondesk, onvault)

## Architecture

Two-layer defense:
- **Layer 1 (macFUSE):** Files encrypted at rest with AES-256-XTS. FUSE mount provides decrypted view only when daemon is running and user authenticated.
- **Layer 2 (ESF):** Endpoint Security Framework controls which processes can access mounted plaintext. Comprehensive AUTH event subscription (AUTH_OPEN, AUTH_RENAME, AUTH_LINK, AUTH_UNLINK, AUTH_TRUNCATE, AUTH_EXEC).

Key hierarchy: Passphrase → Argon2id → Master Key (Secure Enclave wrapped) → Per-Vault Key (HKDF) → Per-File Key (HKDF + nonce xattr).

## Build & Test

```bash
./app.sh --deps          # Install dependencies
./app.sh --build         # Development build
./app.sh --test          # Run all 23 tests
./app.sh --dist          # Static-linked distribution build
./app.sh --check         # Verify system readiness
```

Or directly with Make:
```bash
make clean && make       # Build
make test                # Run tests
make dist                # Distribution build
```

## Dependencies

**Build-time (developer):** OpenSSL 3, libargon2, macFUSE, Xcode CLI Tools
**Runtime (end user):** macFUSE only (everything else statically linked in dist builds)

## Code Structure

```
src/common/     — Shared: crypto, hash, memwipe, argon2, config, ipc, log, types
src/fuse/       — Layer 1: macFUSE encrypted filesystem (encrypt, vault, onvault_fuse)
src/esf/        — Layer 2: ESF per-process control (agent, policy)
src/keystore/   — Secure Enclave + Keychain (ECDH key wrapping)
src/daemon/     — onvaultd main daemon
src/cli/        — onvault CLI
src/menubar/    — macOS menu bar (NSStatusItem via Obj-C runtime)
src/auth/       — Passphrase, session tokens, Touch ID, recovery key
src/watch/      — Learning/discovery mode (ESF NOTIFY observer)
tests/          — Unit + integration tests
defaults/       — Smart default allowlists (ssh.yaml, aws.yaml, kube.yaml)
install/        — launchd plist, entitlements
```

## Key Conventions

- **Naming:** CLI is `onvault`, daemon is `onvaultd`. Protected directories are called "vaults."
- **Branding:** Use "seamless" or "at-rest" when describing encryption. Never reference competing vendor product names or terminology.
- **Crypto:** OpenSSL for AES-XTS/GCM/HKDF (CommonCrypto lacks XTS and GCM). CommonCrypto for SHA-256. libargon2 for passphrase KDF.
- **Obj-C files:** `.m` extension. Use `-fobjc-arc`. Keystore, ESF agent, menubar, and Touch ID are Obj-C.
- **Memory safety:** All keys must be `mlock()`'d and `explicit_bzero()`'d after use via `memwipe.h`.
- **ESF conditional:** ESF code is behind `#ifdef HAVE_ESF`. Builds with stub if SDK not available.
- **FUSE conditional:** FUSE code is behind `#ifdef HAVE_MACFUSE`. Builds with stub if macFUSE not installed.
- **Config encryption:** All onvault config/policies are AES-256-GCM encrypted with a config key derived from the master key.
- **Process verification:** Three modes — `codesign_preferred` (default), `hash_only`, `codesign_required`.

## Git Rules

- **NEVER commit temporary files, build artifacts, or plan files.** The `.gitignore` covers: `*.o`, binaries (`onvault`, `onvaultd`), test binaries, `.DS_Store`, `.claude/`, `plan.md`, `.onvault/`.
- **NEVER push directly to main without user approval.** Every commit must be reviewed and explicitly approved by the user before pushing.
- **NEVER force push.** Always create new commits.
- **Commit messages:** Use conventional commits. Lead with what changed, not how. Example: `feat: add vault watch learning mode` or `fix: handle empty nonce xattr gracefully`.
- **No auto-commits.** Always show the diff and get explicit user confirmation before committing.
- **Branch protection:** `main` is the default branch. All work happens on `main` for now (no feature branches until the team grows).

## Security Practices

- Never log or print encryption keys, passphrases, or key material.
- Never store keys in plaintext on disk. Always Keychain + Secure Enclave.
- Always wipe key material from memory after use.
- Default deny policy — if no rule matches, access is denied.
- Root is not trusted by default. su/sudo detected via audit_token ruid vs euid.
