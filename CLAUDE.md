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

### Daemon Architecture

`onvaultd` runs three concurrent subsystems:
- **IPC server** — Unix domain socket at `~/.onvault/onvault.sock` for CLI commands
- **HTTP server** — localhost-only server for the web-based menu bar UI (port in `~/.onvault/http.port`)
- **Menu bar** — WKWebView popover loading from the HTTP server (or NSApp event loop on main thread)

PID lock at `~/.onvault/onvaultd.pid` prevents multiple daemon instances.

### Auth-Gated IPC

Destructive commands (lock, vault remove) use challenge-response auth:
1. CLI requests nonce via `IPC_CMD_AUTH_CHALLENGE`
2. CLI computes `SHA-256(Argon2id(passphrase, salt) || nonce)`
3. Daemon verifies proof, nonce is single-use (invalidated after verification)

Read-only IPC commands (rules, policy show, vault list) require `g_master_key_loaded` — must be unlocked.

## Build & Test

```bash
make clean && make       # Build (CLI + daemon + tests)
make test                # Run all 25 tests (14 crypto + 11 vault)
make dist                # Static-linked distribution build
```

## Dependencies

**Build-time (developer):** OpenSSL 3, libargon2, macFUSE, Xcode CLI Tools
**Runtime (end user):** macFUSE only (everything else statically linked in dist builds)

## Code Structure

```
src/common/       — Shared: crypto, hash, memwipe, argon2, config, ipc, log, types
src/fuse/         — Layer 1: macFUSE encrypted filesystem (encrypt, vault, onvault_fuse)
src/esf/          — Layer 2: ESF per-process control (agent, policy)
src/keystore/     — Secure Enclave + Keychain (ECDH key wrapping, software fallback)
src/daemon/       — onvaultd: IPC server, HTTP server, embedded web UI (menubar.html)
src/cli/          — onvault CLI: all commands + interactive configure TUI
src/menubar/      — macOS menu bar: WKWebView popover + NSStatusItem + notifications
src/auth/         — Passphrase, session tokens, Touch ID, recovery key, challenge-response
src/watch/        — Learning/discovery mode (ESF NOTIFY observer)
tests/            — Unit + integration tests (keystore_stub.c for pop-up-free testing)
defaults/         — Smart default allowlists (ssh.yaml, aws.yaml, kube.yaml)
install/          — launchd plist, entitlements
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
- **Smart defaults:** Opt-in via `--smart` flag. Auto-populates allowlists for known vault types (ssh, aws, kube, gnupg, docker).
- **Web UI JS:** Must use ES5 syntax (no async/await, use `.then()` chains). WKWebView on older macOS doesn't support top-level await.
- **HTML embedding:** `src/daemon/menubar.html` is the source; it's embedded as a C string in `onvaultd.c` via a Python script during build.
- **Test isolation:** Tests use `tests/keystore_stub.c` (in-memory keystore) to avoid Keychain/iCloud popups.

## IPC Protocol

Socket: `~/.onvault/onvault.sock` (umask 0177, owner-only)

Commands: STATUS, UNLOCK, LOCK, VAULT_ADD, VAULT_REMOVE, VAULT_LIST, ALLOW, DENY, POLICY_SHOW, RULES, WATCH_START, WATCH_SUGGEST, ROTATE_KEYS, LOG, AUTH_CHALLENGE

Auth-gated (need proof): LOCK, VAULT_REMOVE
Session-gated (need unlock): VAULT_ADD, ALLOW, DENY, VAULT_LIST, RULES, POLICY_SHOW, LOG

## HTTP API (localhost only)

GET endpoints: `/menubar`, `/api/status`, `/api/denials`, `/api/policies`, `/api/rules?vault=<id>`
POST endpoints: `/api/unlock`, `/api/lock`, `/api/vault/add`, `/api/allow`, `/api/deny`

All POST bodies are plain text. Thread-per-request to avoid blocking on Argon2id (~2-3s).

## Git Rules

- **NEVER commit temporary files, build artifacts, or plan files.** The `.gitignore` covers: `*.o`, binaries (`onvault`, `onvaultd`), test binaries, `.DS_Store`, `.claude/`, `plan.md`, `.onvault/`, `*.png`, `.playwright-mcp/`.
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
- Destructive IPC commands require challenge-response passphrase proof (single-use nonce).
- Read-only IPC commands require daemon to be unlocked (prevents policy enumeration by attackers).
- IPC payloads validated with `read_all()` — partial reads rejected.
- HTTP server is localhost-only (127.0.0.1), thread-per-request.
- PID lock prevents multiple daemon instances.
- Auto-create policy on first allow/deny rule for a vault.
