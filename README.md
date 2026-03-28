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

**Layer 2 — Per-Process Access Control (Endpoint Security Framework):** Even when the FUSE mount is active, only verified processes can read your files. `/usr/bin/ssh` can read `~/.ssh/id_rsa`. `python3` cannot. Process identity is verified by Apple's code signing (cdHash + Team ID), not just the binary path.

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
make dist   # Distribution build (static linking, no Homebrew needed by users)
```

### Usage

```bash
# First-time setup — sets passphrase, generates recovery key
onvault init

# Start the daemon
onvaultd &

# Protect your SSH keys
onvault vault add ~/.ssh

# Protect AWS credentials
onvault vault add ~/.aws

# Unlock vaults (authenticate with passphrase)
onvault unlock

# Check status
onvault status

# Lock everything (unmount, wipe keys)
onvault lock
```

### Managing Access

```bash
# Allow vim to edit SSH keys
onvault allow /usr/bin/vim ssh

# Deny python from AWS credentials
onvault deny /usr/bin/python3 aws

# See what processes access a path (learning mode)
onvault vault watch ~/.ssh
onvault vault suggest ssh

# View denied access attempts
onvault log --denied
```

---

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  onvault CLI (C)                   │
│        onvault vault, onvault policy, onvault status│
├──────────────────────────────────────────────────┤
│            Menu Bar App (C + Obj-C)               │
│    Status indicator, lock/unlock, notifications    │
├──────────────────────────────────────────────────┤
│             Daemon — onvaultd (C)                  │
│  Policy Engine │ Auth │ Key Mgmt │ Audit Logger   │
├──────────────────────────────────────────────────┤
│                                                    │
│  Layer 1: Encryption at Rest (macFUSE)            │
│  AES-256-XTS (data) + AES-256-GCM (filenames)    │
│  Per-file keys via HKDF-SHA512 + nonce in xattr   │
│  No daemon = no mount = ciphertext only            │
│                                                    │
│  Layer 2: Per-Process Access Control (ESF)        │
│  AUTH_OPEN + AUTH_RENAME + AUTH_LINK + more        │
│  cdHash + Team ID + Signing ID verification        │
│  su/sudo detection via audit_token ruid vs euid    │
│                                                    │
├──────────────────────────────────────────────────┤
│  Secure Enclave + Keychain                        │
│  Master key wrapped via ECDH, non-exportable       │
└──────────────────────────────────────────────────┘
```

### Key Hierarchy

```
User Passphrase
  → [Argon2id, 46 MiB] → Master Key (AES-256)
    → Stored in Secure Enclave (ECDH-wrapped, non-exportable)
    → [HKDF-SHA512] → Per-Vault Key (one per protected directory)
      → [HKDF-SHA512 + nonce] → Per-File Key (unique per file)
```

### Smart Defaults

When you add a vault, onvault suggests an allowlist of known-good binaries:

| Vault | Default Allowed Processes |
|-------|-------------------------|
| `~/.ssh` | ssh, scp, sftp, ssh-add, ssh-agent, ssh-keygen, git |
| `~/.aws` | aws, terraform, pulumi |
| `~/.kube` | kubectl, helm, k9s |
| `~/.gnupg` | gpg, gpg2, gpg-agent, git |
| `~/.docker` | docker, Docker.app |

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
| **Daemon killed / not running** | FUSE auto-unmounts. Files remain AES-256 encrypted on disk. |
| **Physical disk theft** | Encrypted at rest. Master key in Secure Enclave (hardware-bound). |
| **Root / su impersonation** | Detected via `audit_token` — real UID vs effective UID comparison. |
| **Binary swapping** | Process identity verified by cdHash (Apple's content directory hash), not just path. |
| **Config tampering** | All policies and config encrypted with master key derivative. |
| **Memory snooping** | Keys `mlock()`'d (never swapped to disk), `explicit_bzero()`'d after use. |

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

---

## How It Works on Disk

```
~/.onvault/
├── salt                    # Argon2id salt (16 bytes)
├── auth.enc                # Passphrase hash (encrypted)
├── config.enc              # Policies + allowlists (AES-256-GCM)
├── vaults/
│   ├── ssh/                # Ciphertext for ~/.ssh
│   └── aws/                # Ciphertext for ~/.aws
└── mnt/
    ├── ssh/                # FUSE mount → symlinked from ~/.ssh
    └── aws/                # FUSE mount → symlinked from ~/.aws
```

When locked: `~/.ssh` is a symlink to an empty mount point. The actual files are ciphertext in `~/.onvault/vaults/ssh/`.

When unlocked: FUSE mounts decrypt on-the-fly. `~/.ssh/id_rsa` is readable — but only by processes in the allowlist.

---

## Requirements

- **macOS 15 Sequoia** or later (Apple Silicon)
- **macFUSE 5.1+** (`brew install --cask macfuse`)
- No other dependencies (OpenSSL and Argon2 are statically linked)

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
│   ├── keystore/       # Secure Enclave + Keychain integration
│   ├── daemon/         # onvaultd main entry
│   ├── cli/            # onvault CLI
│   ├── menubar/        # macOS menu bar status item
│   ├── auth/           # Passphrase, session tokens, Touch ID, recovery
│   └── watch/          # Learning/discovery mode
├── tests/              # Unit + integration tests
├── defaults/           # Smart default allowlists (ssh, aws, kube)
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
