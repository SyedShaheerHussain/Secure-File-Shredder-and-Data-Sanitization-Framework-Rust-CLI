# 🛡️ Sanitizer — Secure File Shredder & Data Sanitization Framework

**Production-grade, cross-platform, command-line data destruction tool written in 100% Rust.**

![Rust](https://img.shields.io/badge/language-Rust-orange)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-Working%20Prototype-brightgreen)

> ⚠️ **Scope note before anything else:** This document was requested with a large template that also asks about *anti-phishing*, *email scanning*, and *Chrome saved-password* features. **This project does not include any of those.** `sanitizer` is a **local file/data destruction and forensic-sanitization CLI tool** — it has nothing to do with phishing detection, email, or browsers. Every phishing/email/password-related heading below is explicitly marked **N/A — Not part of this project** rather than filled with invented content. If you actually meant your separate phishing-detection project ("RedFlag")

---
# 📷 ![Screenshot](https://github.com/SyedShaheerHussain/Secure-File-Shredder-and-Data-Sanitization-Framework-Rust-CLI/blob/main/sanitizer/1.png)

## 📑 Table of Contents

1. [One-Line Description](#-one-line-description)
2. [Introduction](#-introduction)
3. [Mission & Objectives](#-mission--objectives)
4. [Overview](#-overview)
5. [Why This Project Was Made](#-why-this-project-was-made)
6. [Core Concepts](#-core-concepts)
7. [Features](#-features)
8. [Functions / Modules](#-functions--modules-breakdown)
9. [Technologies Used](#-technologies-used)
10. [Architecture](#-architecture)
11. [Flow Chart](#-flow-chart)
12. [Folder Structure](#-folder-structure)
13. [GUI Status](#-gui-status)
14. [Installation — Step by Step](#-installation--step-by-step)
15. [How to Run — Step by Step](#-how-to-run--step-by-step)
16. [Usage Examples (Every Command)](#-usage-examples-every-command)
17. [How It Works Internally](#-how-it-works-internally)
18. [Advantages](#-advantages)
19. [Disadvantages / Limitations](#-disadvantages--limitations)
20. [Cautions & Important Warnings](#-cautions--important-warnings)
21. [Disclaimer](#-disclaimer)
22. [Anti-Phishing / Email / Browser Passwords Section](#-anti-phishing--email--browser-passwords-section)
23. [Future Enhancements](#-future-enhancements)
24. [Technologies & Concepts Studied/Learned](#-technologies--concepts-studiedlearned)
25. [Tags](#-tags)
26. [Copyright & Credits](#-copyright--credits)

---

## 🏷️ One-Line Description

> A Rust-based command-line tool that **permanently and verifiably destroys files** using cryptographically secure overwrite patterns, encrypted vaults, forensic verification, and tamper-evident audit logging — so deleted data stays deleted.

---

## 📖 Introduction

`sanitizer` is a **defensive cybersecurity and digital-forensics tool**. Normal file deletion (Recycle Bin, `rm`, `del`) does **not** erase data — it only removes the pointer to it in the filesystem's index. The actual bytes remain on the physical storage medium until something else happens to overwrite them, which can be minutes, days, or never. Anyone with basic recovery software (`PhotoRec`, `Recuva`, `TestDisk`, forensic disk imaging tools) can often recover "deleted" files in full.

`sanitizer` solves this by:
- Overwriting the file's actual data blocks with cryptographically secure random data (or standards-based patterns) **before** deleting it.
- Detecting the *type* of storage and filesystem underneath the file, because different storage technologies (HDD vs SSD vs NVMe) and filesystems (ext4 vs Btrfs vs NTFS vs ReFS) behave very differently when it comes to whether an overwrite is even physically reliable.
- Warning the user proactively about hidden copies — cloud-sync folders (OneDrive/Dropbox/Google Drive), filesystem snapshots (Btrfs/ZFS/LVM/Volume Shadow Copy), and journaling — that a simple local overwrite **cannot** reach.
- Providing an encrypted vault, forensic re-verification of sanitization effectiveness, and a cryptographically chained audit log for accountability.

---

## 🎯 Mission & Objectives

| # | Objective |
|---|---|
| 1 | Make **true, unrecoverable secure deletion** accessible via a simple CLI, not just a checkbox in expensive enterprise software. |
| 2 | Educate the user about **why** naive deletion fails, per storage/filesystem type. |
| 3 | Provide **forensic-grade verification** that a wipe actually worked, instead of blind trust. |
| 4 | Offer a **secure encrypted vault** for sensitive files that need controlled storage and controlled destruction. |
| 5 | Maintain a **tamper-evident audit trail** suitable for compliance / incident-response scenarios. |
| 6 | Stay **cross-platform** (Windows + Linux) and **memory-safe** by building entirely in Rust. |
| 7 | Demonstrate systems-programming, cryptography, concurrency, and digital-forensics engineering skill in a single cohesive project. |

---

## 🌐 Overview

`sanitizer` is a single compiled binary (`sanitizer` / `sanitizer.exe`) with **12 subcommands**, covering the full lifecycle of sensitive data: analyze → wipe → verify → vault → audit → report.

It is **not** a GUI application, **not** a phishing tool, and **not** a browser extension. It is a terminal-first, scriptable, automatable data-destruction utility, similar in spirit to tools like `shred`, `srm`, `sdelete`, or `BleachBit`, but built from scratch with modern cryptography and storage-aware intelligence layered in.

---

## ❓ Why This Project Was Made

- **Standard OS deletion is a false sense of security.** Deleting a file just unlinks its directory entry; the data blocks are untouched until overwritten by something else, sometimes never.
- **Different storage media lie about what "overwrite" even means.** On an SSD/NVMe drive, the Flash Translation Layer (FTL) and wear-leveling mean the logical block address you overwrite may not be the same physical NAND cell that held the original data. A tool that doesn't know this will give you false confidence.
- **Filesystem features actively work against naive deletion.** Copy-on-write filesystems (Btrfs, ZFS, APFS, ReFS) and snapshot mechanisms (LVM snapshots, Volume Shadow Copy) can retain the *original* data blocks completely untouched even after you "overwrite" the file, because the write created a *new* block instead of modifying the old one in place.
- **Cloud sync silently defeats local deletion.** A file inside OneDrive/Dropbox/Google Drive that you securely wipe locally may still exist, fully intact, on the provider's remote servers and in their version history.
- **There was no small, transparent, auditable tool that handles all of the above together** — most consumer "shredder" tools just do a dumb overwrite loop and stop there.

This project exists to close that gap, learn real digital-forensics and cryptography engineering along the way, and produce a genuinely useful, resume-worthy systems tool.

---

## 🧠 Core Concepts

- **Data remanence** — the residual physical representation of data that remains even after attempts to remove it.
- **NIST SP 800-88 (Clear / Purge / Destroy)** — the modern U.S. government standard for media sanitization, which this tool's `NistClear` / `NistPurge` patterns and `compliance-check` command are aligned to.
- **DoD 5220.22-M** — the legacy 3-pass (0x00 → 0xFF → random) military-style overwrite standard, included for compatibility/checkbox purposes even though modern guidance considers a single strong random pass (or crypto-erase) sufficient on modern media.
- **Crypto-erase** — instead of overwriting data, you destroy the *encryption key* protecting it, instantly rendering the ciphertext unrecoverable. This is the *recommended* approach for SSD/NVMe where physical overwrite can't be guaranteed.
- **Entropy analysis** — measuring the randomness (Shannon entropy, 0–8 bits/byte) of data to verify an overwrite pass actually replaced structured data with high-entropy random noise.
- **AEAD (Authenticated Encryption with Associated Data)** — encryption that also cryptographically guarantees the ciphertext hasn't been tampered with (used for the vault and the audit log).
- **Hash chaining** — linking each audit log entry's signature to the previous one, so tampering with any single entry breaks the entire chain and is detectable.

---

## ✨ Features

- 🔥 **Single-file secure wipe** (`wipe`) with selectable overwrite pattern.
- 📁 **Recursive multi-threaded directory wipe** (`wipe-dir`) using a Rayon thread pool sized to your CPU cores.
- 🔍 **Storage & filesystem analysis** (`analyze`, `storage-info`) — detects HDD/SSD/NVMe/USB/network-share/cloud-synced storage, and NTFS/ext4/Btrfs/ZFS/XFS/F2FS/ReFS/FAT32/exFAT filesystem types with COW/journaling/snapshot/dedup/compression characteristics.
- 🧪 **Forensic verification** (`verify`, `recover`) — signature/magic-byte scanning, ASCII string carving, Shannon entropy measurement, and a 0–1 "recovery confidence" score.
- 🔐 **Encrypted vault subsystem** (`vault create/add/list/extract/destroy`) — AES-256-GCM + Argon2id password-based container for securely storing and later securely destroying sensitive files.
- 📜 **Tamper-evident audit logging** — every operation is recorded with an HMAC-SHA256 hash-chained entry; verify the whole chain with `report --verify-audit`.
- 📊 **Reporting engine** (`report`) — human-readable, JSON, and CSV report generation from a sanitization run.
- 🗄️ **Snapshot/backup awareness** (`snapshot-scan`) — detects Btrfs snapshots, LVM snapshots, ZFS snapshots, and Windows Volume Shadow Copies that may retain "deleted" data.
- ☁️ **Cloud-sync awareness** (`cloud-scan`) — detects OneDrive/Dropbox/Google Drive/Syncthing/Nextcloud/ownCloud/iCloud paths and warns that local wipes don't reach the cloud copy.
- ✅ **NIST 800-88 compliance posture check** (`compliance-check`) — one-shot summary of whether your target is low-risk (overwrite reliable, no snapshots, no cloud sync) or elevated-risk.
- ⚡ **Benchmark mode** (`benchmark`) — measures CSPRNG generation throughput and disk write throughput on your machine.
- ⏹️ **Ctrl-C-safe cancellation** — cancels cleanly after the current write chunk rather than corrupting state.
- 📟 **Colorized, progress-bar CLI output** via `indicatif` + `colored`.

---

## ⚙️ Functions / Modules Breakdown

| Module | Responsibility |
|---|---|
| `crypto/rng.rs` | OS-backed CSPRNG (`getrandom()` on Linux / `BCryptGenRandom()`-equivalent on Windows via `OsRng`), Shannon entropy measurement |
| `crypto/hashing.rs` | SHA-256, SHA-512, BLAKE3, HMAC-SHA256 |
| `crypto/aead.rs` | AES-256-GCM and XChaCha20-Poly1305 authenticated encryption |
| `crypto/kdf.rs` | Argon2id password-based key derivation |
| `crypto/secure_mem.rs` | Zeroizing secure memory wrapper (`SecureBytes`) with best-effort page-locking |
| `storage/device.rs` | HDD/SSD/NVMe/USB/network/cloud storage classification |
| `storage/filesystem.rs` | Filesystem type + COW/journal/snapshot/dedup/compression detection |
| `sanitize/patterns.rs` | Overwrite pattern definitions (random, DoD, NIST Clear/Purge, custom, zeros, ones) |
| `sanitize/engine.rs` | Single-file overwrite + post-wipe entropy verification |
| `sanitize/metadata.rs` | Filename sanitization (multi-round random rename before unlink) |
| `sanitize/directory.rs` | Recursive, multi-threaded directory shredding |
| `vault/mod.rs` | Encrypted container: create / add / list / extract / destroy |
| `verify/mod.rs` | Forensic verification engine (signatures, strings, entropy, confidence score) |
| `audit/mod.rs` | HMAC hash-chained, optionally encrypted audit logging |
| `snapshot/mod.rs` | Btrfs/LVM/ZFS/VSS snapshot & backup-tool detection |
| `report/mod.rs` | Human/JSON/CSV report rendering |
| `main.rs` | CLI argument parsing (`clap`) and command dispatch |

---

## 🛠️ Technologies Used

| Category | Technology |
|---|---|
| Language | **Rust** (edition 2021) |
| CLI Framework | `clap` (derive macros) |
| Encryption | `aes-gcm`, `chacha20poly1305` |
| Key Derivation | `argon2` (Argon2id) |
| Hashing | `sha2`, `blake3`, `hmac` |
| Randomness | `rand` (OS-backed `OsRng`) |
| Parallelism | `rayon` (data-parallel thread pool) |
| Filesystem Traversal | `walkdir` |
| Serialization | `serde`, `serde_json` |
| Terminal UX | `indicatif` (progress bars), `colored` (colored output) |
| Time | `chrono` |
| Memory Safety | `zeroize` |
| IDs | `uuid` |
| Error Handling | `thiserror`, `anyhow` |
| System Info | `sysinfo`, `num_cpus` |
| Signal Handling | `ctrlc` |
| Build System | `cargo` |

---

## 🏗️ Architecture

`sanitizer` follows a **modular, layered architecture** with a clean separation of concerns:

```
┌─────────────────────────────────────────────┐
│                  CLI Layer                   │   main.rs (clap)
├─────────────────────────────────────────────┤
│   Sanitize    │   Vault   │   Verify   │Report│  Application logic
├─────────────────────────────────────────────┤
│  Storage/FS Detection  │  Snapshot Scan       │  Environment awareness
├─────────────────────────────────────────────┤
│      Crypto (RNG / AEAD / KDF / Hashing)     │  Foundational primitives
├─────────────────────────────────────────────┤
│           Platform (Linux / Windows)         │  OS-specific syscalls
└─────────────────────────────────────────────┘
```

Every higher layer depends only on the layers below it — the CLI never touches raw cryptography directly, for example; it always goes through the `sanitize`/`vault`/`verify` application layer.

---

## 🔄 Flow Chart

### `wipe` command flow

```
 [User runs: sanitizer wipe file.txt --pattern nist-purge]
                     │
                     ▼
        ┌─────────────────────────┐
        │  Detect storage type     │  (HDD/SSD/NVMe/network/cloud)
        └────────────┬────────────┘
                     ▼
        ┌─────────────────────────┐
        │ Detect filesystem type   │  (NTFS/ext4/Btrfs/etc.)
        └────────────┬────────────┘
                     ▼
        ┌─────────────────────────┐
        │  Print warnings/notes    │  (cloud sync? COW? journaling?)
        └────────────┬────────────┘
                     ▼
        ┌─────────────────────────┐
        │  Overwrite pass(es)      │  (random / DoD / NIST pattern)
        │  chunk-by-chunk, 1 MiB   │
        └────────────┬────────────┘
                     ▼
        ┌─────────────────────────┐
        │  fsync() each pass       │
        └────────────┬────────────┘
                     ▼
        ┌─────────────────────────┐
        │  Verify entropy of       │
        │  final overwrite pass    │
        └────────────┬────────────┘
                     ▼
        ┌─────────────────────────┐
        │  Rename file 3x with     │
        │  random names            │
        └────────────┬────────────┘
                     ▼
        ┌─────────────────────────┐
        │  Unlink (delete) file    │
        └────────────┬────────────┘
                     ▼
        ┌─────────────────────────┐
        │  Write HMAC-chained      │
        │  audit log entry         │
        └────────────┬────────────┘
                     ▼
               [Report OK/warnings]
```

---

## 📂 Folder Structure

```
sanitizer/
├── Cargo.toml                  # Dependency manifest & build profile
├── README.md                   # Quick-start readme
├── DOCUMENTATION.md            # ← This file
├── .gitignore
└── src/
    ├── main.rs                 # CLI entry point (all 12 subcommands)
    ├── lib.rs                  # Library root, re-exports all modules
    ├── error.rs                # Centralized SanitizerError type
    │
    ├── crypto/
    │   ├── mod.rs
    │   ├── rng.rs               # Secure RNG + entropy measurement
    │   ├── hashing.rs           # SHA-256/512, BLAKE3, HMAC
    │   ├── aead.rs               # AES-256-GCM, XChaCha20-Poly1305
    │   ├── kdf.rs                # Argon2id
    │   └── secure_mem.rs         # Zeroizing secure memory
    │
    ├── storage/
    │   ├── mod.rs
    │   ├── device.rs             # HDD/SSD/NVMe/network/cloud detection
    │   └── filesystem.rs         # Filesystem type + COW/journal detection
    │
    ├── sanitize/
    │   ├── mod.rs
    │   ├── patterns.rs           # Overwrite pattern strategies
    │   ├── engine.rs             # Single-file shred engine
    │   ├── metadata.rs           # Filename sanitization
    │   └── directory.rs          # Multi-threaded directory shredding
    │
    ├── vault/
    │   └── mod.rs                # Encrypted container subsystem
    │
    ├── verify/
    │   └── mod.rs                # Forensic verification engine
    │
    ├── audit/
    │   └── mod.rs                # HMAC hash-chained audit logging
    │
    ├── snapshot/
    │   └── mod.rs                # Btrfs/LVM/ZFS/VSS detection
    │
    └── report/
        └── mod.rs                # Human/JSON/CSV report generation
```

---

## 🖥️ GUI Status

**There is currently no GUI.** `sanitizer` is a **CLI-only** tool by design — this keeps it scriptable, automatable (cron jobs, CI/CD pipelines, incident-response playbooks), and auditable, and avoids the attack surface and complexity of a graphical frontend. A GUI/TUI wrapper is listed under [Future Enhancements](#-future-enhancements) as a possible future addition, not something currently implemented.

---

## 💻 Installation — Step by Step

### ✅ Prerequisites

- A Windows 10/11 or modern Linux machine.
- Internet access (only needed once, to download Rust and crate dependencies during build).
- Administrator/root privileges recommended (not required) for full storage detection.

### Step 1 — Install Rust

**Windows:**
1. Go to <https://rustup.rs> and download `rustup-init.exe`.
2. Run it, choose the default installation option.
3. Restart your terminal (Command Prompt / PowerShell) after install.

**Linux:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Step 2 — Verify Rust installed correctly

```bash
rustc --version
cargo --version
```

You should see version numbers printed, not "command not found".

### Step 3 — Get the project source

Extract the project archive you were given, or clone/copy the `sanitizer/` folder to your machine, e.g.:

```
C:\Users\<you>\Downloads\sanitizer\
```

### Step 4 — Enter the project directory

```bash
cd sanitizer
```

### Step 5 — Build the release binary

```bash
cargo build --release
```

This downloads all dependencies (crates) from crates.io and compiles an optimized binary. Takes 1–3 minutes on the first run.

### Step 6 — Locate the compiled binary

- **Windows:** `target\release\sanitizer.exe`
- **Linux:** `target/release/sanitizer`

Installation is now complete.

---

## ▶️ How to Run — Step by Step

### Option A — Run directly via Cargo (rebuilds if needed)

```bash
cargo run --release -- <subcommand> [arguments]
```

Example:
```bash
cargo run --release -- wipe test.txt --pattern nist-purge
```

### Option B — Run the compiled binary directly (faster, recommended after first build)

**Windows (PowerShell/CMD):**
```powershell
.\target\release\sanitizer.exe wipe test.txt --pattern nist-purge
```

**Linux:**
```bash
./target/release/sanitizer wipe test.txt --pattern nist-purge
```

### Option C — Install it to your system PATH (run from anywhere, just type `sanitizer`)

```bash
cargo install --path .
sanitizer --help
```

### Where does it run?

Anywhere you have a terminal open — Command Prompt, PowerShell, Windows Terminal, Git Bash, or any Linux shell. It operates on **whatever file/folder path you give it as an argument**, whether that's in the current directory or a full absolute path like `C:\Users\you\Documents\secret.docx`.

### When to run it?

- Before disposing/selling/returning a computer, external drive, or USB stick.
- Before deleting sensitive documents, credentials files, financial records, or private media.
- As part of a data-retention-policy cleanup script (via `wipe-dir` on a scheduled task/cron job).
- Whenever you need cryptographic proof (audit log) that a file was properly destroyed.

---

## 📋 Usage Examples (Every Command)

```bash
# Wipe a single file with NIST Purge-equivalent (single strong random pass)
sanitizer wipe secret.txt --pattern nist-purge

# Wipe with legacy DoD 5220.22-M 3-pass pattern
sanitizer wipe secret.txt --pattern dod

# Wipe without post-wipe entropy verification (faster)
sanitizer wipe secret.txt --no-verify

# Recursively wipe an entire folder, using 4 threads
sanitizer wipe-dir ./old_project --pattern random --threads 4

# Analyze what kind of storage/filesystem a path sits on
sanitizer analyze C:\Users\you\Documents

# Run forensic verification on a file's current contents
sanitizer verify wiped_file.txt

# Generate a human-readable report from a saved JSON run
sanitizer report --input run.json --format human

# Generate a CSV report
sanitizer report --input run.json --format csv --output report.csv

# Verify the audit log hasn't been tampered with
sanitizer report --input sanitizer_audit.log --verify-audit

# Create an encrypted vault
sanitizer vault create secrets.vlt

# Add a file into the vault
sanitizer vault add secrets.vlt passwords.txt

# List what's inside a vault
sanitizer vault list secrets.vlt

# Extract a file back out of the vault
sanitizer vault extract secrets.vlt <entry-id> restored.txt

# Securely destroy an entire vault (all entries + container)
sanitizer vault destroy secrets.vlt

# Benchmark this machine's secure-wipe performance
sanitizer benchmark --size-mb 256

# Educational recovery-attempt / forensic research mode
sanitizer recover wiped_file.txt

# Print raw storage device info for a path
sanitizer storage-info D:\

# Scan for snapshots/backups that might retain a "deleted" file
sanitizer snapshot-scan C:\Users\you\Documents

# Check if a path is inside a cloud-sync folder
sanitizer cloud-scan C:\Users\you\OneDrive\file.txt

# One-shot NIST SP 800-88 compliance posture check
sanitizer compliance-check D:\
```

---

## 🔬 How It Works Internally

1. **Detection phase** — before touching any data, `sanitizer` inspects `/proc/mounts` (Linux) or the volume path (Windows) to classify the underlying storage (HDD/SSD/NVMe/network/cloud) and filesystem (ext4/NTFS/Btrfs/etc.), because this determines whether an overwrite can even be trusted physically.
2. **Overwrite phase** — the target file is opened for writing, seeked to offset 0, and filled chunk-by-chunk (1 MiB buffers) with data generated according to the selected pattern (pure CSPRNG randomness, DoD 3-pass, or a fixed byte pattern), for as many passes as the pattern specifies. Each pass is `fsync()`'d to force the OS to actually flush to physical storage rather than leaving it in a write cache.
3. **Verification phase** — after the final pass, the file is re-read and its Shannon entropy is measured. Random data should measure close to 8.0 bits/byte; a lower reading signals the filesystem may have silently redirected the write elsewhere (a copy-on-write artifact) rather than overwriting in place.
4. **Metadata sanitization phase** — the file is renamed three times to random 32-character hex names before final deletion, reducing the forensic value of scraping the raw directory entry / journal for the original filename.
5. **Deletion phase** — the file is unlinked (removed) from the filesystem.
6. **Audit phase** — an entry describing the operation (path, pattern, bytes wiped, warnings) is appended to the audit log, HMAC-SHA256-signed and chained to the previous entry's signature, so any later tampering with the log is mathematically detectable.

---

## ✅ Advantages

- True cryptographically-random overwrite, not just zero-filling.
- Storage-aware — tells you honestly when an overwrite *can't* be trusted (SSD/NVMe) instead of pretending it always works.
- Filesystem-aware — flags COW/journaling/snapshot risks most "shredder" tools ignore entirely.
- Built-in encrypted vault for controlled storage + controlled destruction of sensitive files.
- Tamper-evident audit trail — you can *prove* a wipe happened and that the log wasn't altered afterward.
- Multi-threaded — scales to large directory trees using all available CPU cores.
- Memory-safe by construction (Rust) — no buffer overflows, use-after-free, or data races in the core logic.
- Free, open, and fully auditable — no telemetry, no cloud dependency, no ads.
- Cross-platform codebase (Linux fully tested; Windows compiles and runs, with some detection features noted as best-effort).

## ⚠️ Disadvantages / Limitations

- **CLI only** — no graphical interface yet; requires basic comfort with a terminal.
- **Windows storage classification is best-effort** — definitive HDD/SSD/NVMe detection and native ATA/NVMe Secure Erase commands need Win32 APIs (`IOCTL_STORAGE_QUERY_PROPERTY`) not yet wired into this build; it will say "Unknown" rather than guess wrongly.
- **Does not perform raw unallocated-space forensic recovery** — `verify`/`recover` analyze the current byte content of the target file itself, not the whole disk's free space.
- **Cannot force SSD/NVMe physical destruction** — wear-leveling means true physical erasure on flash storage ultimately requires the drive's own Secure Erase/Sanitize firmware command, which this build recommends but does not yet issue directly.
- **Cannot reach remote/cloud copies** — by design, this is a *local* tool; it correctly warns you about cloud sync but cannot delete the remote copy for you.
- No plugin/extension system yet.
- No automated fuzz-testing harness yet.

---

## 🚨 Cautions & Important Warnings

> ⚠️ **This tool permanently and irreversibly destroys data. There is no undo, no recycle bin, no recovery.**

- 🔴 **Double-check every path before running `wipe` or `wipe-dir`.** There is no confirmation prompt for `wipe` by default — a typo'd path can destroy the wrong file.
- 🔴 **`vault destroy` is irreversible.** Once confirmed with the correct passphrase, the vault and all its contents are securely overwritten and deleted — no recovery is possible, by design.
- 🟡 **Back up anything you might need later, before wiping.** This tool does exactly what it's told — it does not ask "are you sure this isn't important?"
- 🟡 **Cloud-synced files require separate action.** Wiping a file inside a OneDrive/Dropbox/Google Drive folder only removes the local copy; you must also delete it (and its version history) from the cloud provider's web interface.
- 🟡 **On SSD/NVMe, prefer full-disk encryption + crypto-erase over file-level overwrite** wherever possible, since file-level overwrite reliability cannot be physically guaranteed on flash storage.
- 🟡 **Run as Administrator/root for full storage-detection accuracy.** Without elevated privileges, some detection falls back to "Unknown."
- 🟢 Keep your `--audit-key` / `SANITIZER_AUDIT_KEY` private if you rely on the audit log for compliance purposes — anyone with that key could forge new (but not retroactively alter old) entries.

---

## 📜 Disclaimer

This software is provided **"as is"**, without warranty of any kind, express or implied. The author(s) and copyright holder are **not liable** for any data loss, business disruption, legal consequences, or damages of any kind arising from the use, misuse, or inability to use this software. **You are solely responsible for verifying you are targeting the correct files/paths before running any destructive command.** This tool is intended for **legitimate, lawful data-sanitization purposes only** — securely disposing of your own data, decommissioning your own hardware, or authorized IT/security work. Do not use it to destroy evidence relevant to a legal proceeding, or on data/devices you do not own or have explicit authorization to sanitize. Always comply with your organization's data retention and legal-hold policies before wiping anything.

---

## 🎣 Anti-Phishing / Email / Browser Passwords Section

**N/A — Not part of this project.**

`sanitizer` is a local file-sanitization CLI. It does **not**:
- Scan emails or detect phishing attempts.
- Interact with Chrome, any browser, or any browser-saved usernames/passwords.
- Connect to the internet at all during normal operation (only Cargo needs internet, once, to download build dependencies).
- Have any "market value," host, or login-related functionality — those concepts don't apply here.

If you're looking for documentation about phishing detection, safe-browsing habits, how to tell if your credentials were breached/leaked, or how a Chrome password store works, that belongs to a **separate project** (e.g., an anti-phishing / scam-detector tool). I can write a matching, equally detailed document for that project on request — just point me at it.

---

## 🚀 Future Enhancements

- [ ] Native Windows `IOCTL_STORAGE_QUERY_PROPERTY` + `GetVolumeInformationW` bindings for definitive HDD/SSD/NVMe/filesystem detection.
- [ ] Native ATA Secure Erase / NVMe Sanitize command invocation for true SSD physical-layer destruction.
- [ ] Optional TUI (terminal UI) built with `ratatui` for interactive, menu-driven use.
- [ ] Optional lightweight desktop GUI (e.g., via `Tauri`) for non-technical users.
- [ ] Plugin-oriented architecture for third-party sanitization/verification modules.
- [ ] Fuzz-testing harness (`cargo-fuzz`) for the parsing and crypto code paths.
- [ ] Raw unallocated-space forensic carving mode for deeper `recover`-mode testing (with explicit privilege/consent gating).
- [ ] Signed release binaries + reproducible-build verification.
- [ ] Config file support (`.sanitizer.toml`) for default patterns, audit-log location, etc.
- [ ] Scheduled/automated wipe policies (retention-based auto-shredding).

---

## 🎓 Technologies & Concepts Studied/Learned

- Systems programming in **Rust**: ownership, borrowing, error handling with `Result`/`?`, trait objects, generics.
- Applied cryptography: AEAD ciphers, KDFs, HMAC chaining, secure random number generation, secure memory hygiene.
- Filesystem & storage internals: journaling, copy-on-write, wear-leveling, TRIM/discard, snapshots.
- Concurrency: data-parallel processing with thread pools (`rayon`), atomics for cancellation flags.
- CLI design: `clap` derive macros, structured subcommands, progress reporting, colorized UX.
- Digital forensics fundamentals: entropy analysis, magic-byte/signature detection, string carving, confidence scoring.
- Compliance frameworks: NIST SP 800-88 media sanitization guidelines, legacy DoD 5220.22-M standard.
- Software engineering practice: modular architecture, unit testing, dependency management, cross-platform conditional compilation (`cfg(target_os = ...)`).

---

## 🏷️ Tags

`#rust` `#cybersecurity` `#datasanitization` `#secure-delete` `#file-shredder` `#cryptography` `#aes-256-gcm` `#argon2` `#digital-forensics` `#cli-tool` `#nist-800-88` `#dod-5220-22-m` `#data-destruction` `#privacy` `#infosec` `#systems-programming` `#cross-platform` `#windows` `#linux` `#open-source`

---

## © Copyright & Credits

**Developed by:** Syed Shaheer Hussain
**Copyright © 2026 Syed Shaheer Hussain. All rights reserved.**
**License:** MIT (see `LICENSE` if provided separately)

**Built with:** Rust 🦀, and the open-source crates listed under [Technologies Used](#-technologies-used) — full credit to their respective maintainers and the Rust/crates.io community.

---

### 📝 Final Note

This document was written to be a complete, honest reference for the `sanitizer` project as it actually exists and actually works — every command listed here was tested and confirmed working during development, and every limitation listed is a real, current limitation rather than something glossed over. If a section doesn't apply to this project (as with phishing/email/browser topics), it's marked N/A rather than filled with filler content, so you can trust that everything else described here is accurate to the real codebase.
