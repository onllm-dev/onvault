# onvault

**Seamless file encryption & per-process access control for macOS.**

Protect `~/.ssh`, `~/.aws`, `~/.kube`, and other sensitive directories from supply chain attacks, malicious packages, and unauthorized processes. Files are encrypted at rest and only decrypted for verified, code-signed binaries.

**Links:** [Website](https://onvault.onllm.dev) | [Buy Me a Coffee](https://buymeacoffee.com/prakersh)

**Trust & Quality**

[![Stars](https://img.shields.io/github/stars/onllm-dev/onvault?style=for-the-badge&logo=github&logoColor=white&label=Stars&color=181717)](https://github.com/onllm-dev/onvault/stargazers)
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-brightgreen?style=for-the-badge&logo=gnu&logoColor=white)](LICENSE)
[![Platform](https://img.shields.io/badge/macOS%2015+-orange?style=for-the-badge&logo=apple&logoColor=white)](#quick-start)
[![Language](https://img.shields.io/badge/C-00599C?style=for-the-badge&logo=c&logoColor=white)](#architecture)

**Zero telemetry. Single binary. All data stays on your machine.**

> Powered by [onllm.dev](https://onllm.dev)

---

## The Problem

Supply chain attacks like the [litellm credential stealer](https://github.com/BerriAI/litellm/issues/24512) (March 2026) demonstrate a critical gap: **any process running as your user can read your SSH keys, AWS credentials, and Kubernetes configs.** Standard Unix permissions offer no protection against same-user attacks.

A malicious PyPI/npm package runs as you. It reads `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.kube/config` — and exfiltrates everything. FileVault doesn't help (it's full-disk, not per-process). No existing macOS tool combines file encryption with per-process access control.

## How onvault Solves This

onvault uses a **two-layer defense**:

**Layer 1 — Encryption at Rest (macFUSE):** Your sensitive directories are encrypted on disk. Files are only decrypted through a FUSE mount when onvault is running and you've authenticated. Kill the daemon? Files stay encrypted. Attacker reads disk? Ciphertext only.

**Layer 2 — Per-Process Access Control (Endpoint Security Framework, when available):** On builds/runtimes with the required ESF entitlement and permissions, only verified processes can read mounted plaintext. `/usr/bin/ssh` can read `~/.ssh/id_rsa`. `python3` cannot. Process identity is verified by Apple's code signing (cdHash + Team ID), not just the binary path.

```
Malicious package runs → tries to read ~/.ssh/id_rsa
  → Layer 2: python3 not in allowlist → DENIED
  → Even without Layer 2: file on disk is AES-256-XTS ciphertext

You run `ssh user@host`:
  → Layer 2: /usr/bin/ssh is in allowlist, Apple-signed → ALLOWED
  → Layer 1: FUSE decrypts on-the-fly → SSH reads the key
```

---

## Quick Start

### Prerequisites

```bash
# macFUSE (one-time, requires reboot)
brew install --cask macfuse
# Approve the system extension in System Settings → Privacy & Security
# Reboot
```

### Build from Source

```bash
git clone https://github.com/onllm-dev/onvault.git
cd onvault
make        # Development build
make test   # Run test suite (25 tests)
make dist   # Distribution build (macFUSE still required at runtime)
```

### Usage

```bash
# 1. First-time setup — sets passphrase, generates a recovery key display
onvault init

# 2. Start the daemon (shows menu bar icon + web UI)
onvaultd &                  # with menu bar
onvaultd --no-gui &         # headless (servers, CI)

# 3. Unlock — authenticates, loads the master key, and mounts configured vaults
onvault unlock

# 4. Protect directories — encrypts files, creates symlink
onvault vault add ~/.ssh --smart  # encrypt + auto-populate allowlist
onvault vault add ~/.aws --smart  # encrypt AWS credentials

# 5. Status — see what's protected
onvault status

# 6. Lock — unmount vaults, wipe keys from memory (passphrase required)
onvault lock
```

Recovery keys are displayed during `onvault init` today; restore/import flows are still planned.

### Menu Bar & Web UI

The daemon shows a menu bar icon and serves an interactive web UI. Click the lock icon or open `http://127.0.0.1:<port>/menubar` in any browser.
The web UI unlock flow returns a localhost-only bearer token; subsequent API calls use that token rather than unauthenticated localhost access.

Everything can be done from the menu bar — no CLI needed:

- **Unlock/Lock** — passphrase dialog, Argon2id verification
- **Add Vault** — type a path, click Protect (auto-creates directory if needed)
- **Allow/Deny Process** — inline input per vault
- **View Rules** — overlay panel showing all rules for a vault
- **View All Policies** — overlay panel with full policy summary
- **Recent Denials** — denied access attempts with quick-allow button
- **Auto-refresh** — vault status updates every 5 seconds

The web UI port is written to `~/.onvault/http.port` for scripting and testing.

### What Happens When You Add a Vault

```
onvault vault add ~/.ssh --smart
```

1. Files in `~/.ssh/` are encrypted (AES-256-XTS) and moved to `~/.onvault/vaults/ssh/`
2. A nonce is stored in each file's xattr for key derivation
3. `~/.ssh` is replaced with a symlink → `~/.onvault/mnt/ssh/`
4. Smart defaults auto-populate 7 allow rules (ssh, scp, sftp, ssh-add, ssh-agent, ssh-keygen, git)
5. When unlocked: FUSE mount decrypts on-the-fly. `ssh`, `git`, etc. work normally.
6. When locked or daemon stops: FUSE unmounts. `~/.ssh` symlink points to nothing. Files are ciphertext.

To undo: `onvault vault remove ssh` decrypts everything back to the original location (passphrase required).

### Auth-Gated Operations

Destructive operations require passphrase verification via challenge-response. A malicious script running as your user **cannot** disable onvault without knowing your passphrase:

| Operation | Auth Required |
|-----------|--------------|
| `onvault lock` | Challenge-response passphrase proof |
| `onvault vault remove` | Challenge-response passphrase proof |
| `onvault configure` | Local passphrase verification |
| Menu bar Lock/Unlock/Add | Passphrase dialog (Argon2id) |
| `onvault unlock` | Passphrase (Argon2id) |
| `onvault vault add` | Session (must be unlocked) |
| `onvault allow/deny` | Challenge-response passphrase proof |
| `onvault status/rules/log` | Requires unlocked daemon |

The daemon uses short-lived single-use nonces for challenge-response — proofs cannot be replayed.

### Smart Defaults

Pass `--smart` when adding a vault for a known directory to auto-populate an allowlist of verified binaries. Smart defaults are opt-in; without `--smart`, the vault starts with default-deny rules until you add explicit allow entries.

| Path | Auto-allowed |
|------|-------------|
| `~/.ssh` | ssh, scp, sftp, ssh-add, ssh-agent, ssh-keygen, git |
| `~/.aws` | aws, terraform, pulumi |
| `~/.kube` | kubectl, helm, k9s |
| `~/.gnupg` | gpg, gpg2, gpg-agent, git |
| `~/.docker` | docker, Docker.app |

Only binaries that exist on your system are added. Each binary is hash-verified.

### Managing Access Policies

Only processes in the allowlist can read your encrypted files. Everything else is denied by default.

```bash
# Allow a specific binary to access a vault
onvault allow /usr/bin/vim ssh

# Deny a specific binary
onvault deny /usr/bin/python3 ssh

# View rules for a vault
onvault rules ssh

# View all policies across vaults
onvault policy show

# See what processes access a path (learning mode — observe for 24h)
onvault vault watch ~/.ssh
onvault vault suggest ssh

# View audit log (all events or denied only)
onvault log
onvault log --denied

# Interactive configuration (passphrase required)
onvault configure
```

### CLI Reference

```
onvault init                          First-time setup
onvault unlock                        Authenticate and mount vaults
onvault lock                          Unmount vaults, wipe keys (passphrase)
onvault status                        Show daemon and vault status
onvault vault add <path> [--smart]    Encrypt and protect a directory
onvault vault remove <vault_id>       Decrypt and unprotect (passphrase)
onvault vault list                    List all vaults
onvault vault watch <path>            Learning mode (24h observation)
onvault vault suggest <vault_id>      Show watch suggestions
onvault allow <process> <vault_id>    Allow a process
onvault deny <process> <vault_id>     Deny a process
onvault rules <vault_id>              Show rules for a vault
onvault policy show                   Show all policies
onvault log [--denied]                View audit log
onvault configure                     Interactive configuration (passphrase)
onvault --version                     Show version
```

Planned, not yet implemented: `policy edit`, `rotate-keys`, `export-recovery`.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│                    onvault CLI (C)                     │
│  init, unlock, lock, vault, allow, deny, configure    │
├──────────────────────────────────────────────────────┤
│      Menu Bar (WKWebView + HTML/CSS/JS popover)       │
│  Vault mgmt, allow/deny, rules, denials, lock/unlock  │
├──────────────────────────────────────────────────────┤
│               Daemon — onvaultd (C)                    │
│  IPC Server │ HTTP Server │ Policy │ Auth │ Audit Log  │
├──────────────────────────────────────────────────────┤
│                                                        │
│  Layer 1: Encryption at Rest (macFUSE)                │
│  AES-256-XTS (data) + AES-256-GCM (filenames)        │
│  Per-file keys via HKDF-SHA512 + nonce in xattr       │
│  No daemon = no mount = ciphertext only                │
│                                                        │
│  Layer 2: Per-Process Access Control (ESF, when       │
│  entitlement + permission are available)              │
│  AUTH_OPEN + AUTH_RENAME + AUTH_LINK + more            │
│  cdHash + Team ID + Signing ID verification            │
│  su/sudo detection via audit_token ruid vs euid        │
│                                                        │
├──────────────────────────────────────────────────────┤
│  Secure Enclave + Keychain                            │
│  Master key wrapped via ECDH, non-exportable           │
│  Software EC key fallback for unsigned binaries        │
└──────────────────────────────────────────────────────┘
```

### Key Hierarchy

```
User Passphrase
  → [Argon2id, 46 MiB] → Master Key (AES-256)
    → Stored in Secure Enclave (ECDH-wrapped, non-exportable)
    → [HKDF-SHA512] → Per-Vault Key (one per protected directory)
      → [HKDF-SHA512 + nonce] → Per-File Key (unique per file)
```

### Process Verification Modes

| Mode | Behavior |
|------|----------|
| `codesign_preferred` (default) | Trust Apple code signing (cdHash + Team ID) for signed binaries. SHA-256 hash for unsigned. Survives brew updates. |
| `hash_only` | Always verify by SHA-256 binary hash. Every update requires re-approval. Maximum paranoia. |
| `codesign_required` | Only allow code-signed binaries. Reject all unsigned. |

---

## Security Model

### Protected Against

| Threat | How |
|--------|-----|
| **Supply chain attacks** (litellm, malicious npm/pip packages) | Malicious code reads only ciphertext. Not in allowlist → DENIED. |
| **Unauthorized daemon shutdown** | `onvault lock` requires passphrase via challenge-response. IPC socket is owner-only. |
| **Daemon killed / not running** | FUSE auto-unmounts. Files remain AES-256 encrypted on disk. |
| **Physical disk theft** | Encrypted at rest. Master key in Secure Enclave (hardware-bound). |
| **Root / su impersonation** | Detected via `audit_token` — real UID vs effective UID comparison. |
| **Binary swapping** | Process identity verified by cdHash (Apple's content directory hash), not just path. |
| **Config tampering** | All policies and config encrypted with master key derivative. |
| **Memory snooping** | Keys `mlock()`'d (never swapped to disk), `explicit_bzero()`'d after use. |
| **IPC replay attacks** | Challenge-response with short-lived single-use nonces for lock, vault remove, allow, and deny. |
| **Policy enumeration** | Read-only IPC commands require unlocked daemon. |
| **Multiple daemon instances** | PID lock file at `~/.onvault/onvaultd.pid`. |

### Not Protected Against

- Kernel-level compromise (ring-0 attacker with code execution)
- Hardware side-channel attacks (Spectre, cold boot on DRAM)
- Compromise of the Secure Enclave hardware itself

### Cryptography

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| File data encryption | AES-256-XTS | NIST SP 800-38E |
| Filename encryption | AES-256-GCM | NIST SP 800-38D |
| Key wrapping | AES-256-GCM | NIST SP 800-38D |
| Passphrase KDF | Argon2id (46 MiB, 1 iter) | RFC 9106, OWASP 2025 |
| Key derivation | HKDF-SHA512 | RFC 5869 |
| Process hashing | SHA-256 | FIPS 180-4 |
| Master key storage | Secure Enclave (ECDH P-256) | Apple CryptoKit |
| Auth proof | SHA-256(key \|\| nonce) | Challenge-response |

---

## How It Works on Disk

```
~/.onvault/
├── salt                    # Argon2id salt (16 bytes)
├── auth.enc                # Passphrase hash (encrypted)
├── onvaultd.pid            # PID lock (prevents multiple daemons)
├── onvault.sock            # IPC socket (CLI ↔ daemon)
├── http.port               # HTTP server port for web UI
├── session                 # Session token + HMAC (15 min TTL)
├── policies.enc            # Encrypted persisted policy state
├── logs/                   # Encrypted audit logs (daily rotation)
├── vaults/
│   ├── ssh/                # Ciphertext for ~/.ssh
│   └── aws/                # Ciphertext for ~/.aws
└── mnt/
    ├── ssh/                # FUSE mount → symlinked from ~/.ssh
    └── aws/                # FUSE mount → symlinked from ~/.aws
```

---

## Requirements

- **macOS 15 Sequoia** or later (Apple Silicon)
- **macFUSE 5.1+** (`brew install --cask macfuse`)
- Dist builds still require macFUSE at runtime

### Build Requirements (developers only)

- Xcode Command Line Tools (`xcode-select --install`)
- OpenSSL 3 (`brew install openssl`)
- libargon2 (`brew install argon2`)
- macFUSE (`brew install --cask macfuse`)

---

## Project Structure

```
onvault/
├── src/
│   ├── common/         # Crypto, hashing, IPC, config, logging, types
│   ├── fuse/           # Layer 1: macFUSE encrypted filesystem
│   ├── esf/            # Layer 2: Endpoint Security per-process control
│   ├── keystore/       # Secure Enclave + Keychain (software fallback)
│   ├── daemon/         # onvaultd: IPC server, HTTP server, web UI
│   ├── cli/            # onvault CLI + interactive configure
│   ├── menubar/        # macOS menu bar: WKWebView popover
│   ├── auth/           # Passphrase, sessions, Touch ID, challenge-response
│   └── watch/          # Learning/discovery mode
├── tests/              # Unit + integration tests
├── defaults/           # Smart default allowlists (ssh, aws, kube, gnupg, docker)
├── install/            # launchd plist, entitlements
├── Makefile
└── LICENSE             # GPL-3.0
```

---

## Competitive Landscape

No existing macOS product combines file encryption with per-process access control:

| Product | Encryption | Per-Process Control | Open Source |
|---------|-----------|-------------------|-------------|
| **onvault** | AES-256-XTS (FUSE) | ESF + code signing | GPL-3.0 |
| FileVault | Full-disk (APFS) | None | No |
| Santa (NorthPoleSec) | None | ESF-based | Yes |
| Cryptomator | AES-256-GCM (FUSE) | None | Yes |
| CrowdStrike Falcon | None | Partial (behavioral) | No |

---

## Contributing

Contributions welcome. Please open an issue before submitting large PRs.

```bash
# Build and test
make clean && make test

# Run all 25 tests
make test
```

---

## License

[GNU General Public License v3.0](LICENSE)

---

> Powered by [onllm.dev](https://onllm.dev)
