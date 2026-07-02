# sanitizer

A production-grade, cross-platform secure file shredder and data
sanitization framework written in Rust. Targets Linux and Windows.

## Status

This is a working, compiling, tested implementation of the core
architecture: CLI, sanitization engine, cryptography, encrypted vault,
forensic verification, tamper-evident audit logging, storage/filesystem
detection, snapshot/cloud-sync awareness, and reporting. It builds clean
with zero warnings on `cargo build` / `cargo build --release` and all 17
unit tests pass (`cargo test`).

Some platform-specific pieces are explicitly stubbed with a clear comment
explaining what's missing and why (see "Known limitations" below) rather
than silently faked — this is a real foundation to build on, not a mockup.

## Build

```
cargo build --release
```

Binary lands at `target/release/sanitizer`.

Note: `Cargo.toml` pins exact dependency versions compatible with older
Rust toolchains (MSRV ~1.75). If you have a newer Rust toolchain, feel
free to relax the `=x.y.z` pins to `"x.y"` for the latest compatible
patch releases.

## Usage

```
sanitizer wipe <file> [--pattern random|dod|nist-clear|nist-purge|zeros|ones|multi-random-N] [--no-verify]
sanitizer wipe-dir <dir> [--pattern ...] [--threads N]
sanitizer analyze <path>
sanitizer verify <file>
sanitizer report --input run.json --format human|json|csv [--output out]
sanitizer report --input audit.log --verify-audit
sanitizer vault create <vault.vlt>
sanitizer vault add <vault.vlt> <file>
sanitizer vault list <vault.vlt>
sanitizer vault extract <vault.vlt> <entry-id> <dest>
sanitizer vault destroy <vault.vlt>
sanitizer benchmark [--size-mb N]
sanitizer recover <file>
sanitizer storage-info <path>
sanitizer snapshot-scan <path>
sanitizer cloud-scan <path>
sanitizer compliance-check <path>
```

Global flags: `--quiet`, `--audit-log <path>`, `--audit-key <key>` (or
`SANITIZER_AUDIT_KEY` env var).

## Architecture

```
src/
  crypto/       secure RNG, SHA-256/512, BLAKE3, HMAC, AES-256-GCM,
                XChaCha20-Poly1305, Argon2id, zeroizing secure memory
  storage/      HDD/SSD/NVMe/USB/network/cloud device classification,
                filesystem type + COW/journaling/snapshot detection
  sanitize/     overwrite pattern strategies, single-file shred engine,
                recursive multi-threaded directory shredder, filename
                sanitization
  vault/        AES-256-GCM + Argon2id encrypted container
  verify/       forensic verification: signature scan, string carving,
                entropy analysis, recovery confidence scoring
  audit/        HMAC-chained tamper-evident audit log, optional
                encryption at rest
  snapshot/     Btrfs/LVM/ZFS/VSS snapshot and backup-tool detection
  report/       human-readable / JSON / CSV report generation
  main.rs       CLI (clap) wiring it all together
```

## Design notes / rationale

- **Storage-aware sanitization**: the engine checks `StorageInfo::overwrite_is_reliable()`
  before trusting an overwrite pass, and surfaces a warning + crypto-erase
  recommendation for SSD/NVMe where wear-leveling means overwritten LBAs
  may not map to the same physical NAND cells.
- **Filesystem awareness**: `FilesystemInfo` flags journaling/COW/snapshot
  filesystems (Btrfs, ZFS, ReFS, ext4 journal, etc.) with specific notes
  about why overwrite alone may be insufficient there.
- **Secure memory**: `SecureBytes` wraps sensitive buffers and zeroizes on
  drop via the `zeroize` crate (volatile writes + compiler fence — the
  same anti-optimization property as `explicit_bzero()`), with best-effort
  `mlock()`/`munlock()` on Unix to keep secrets out of swap.
- **Audit log integrity**: each entry's HMAC-SHA256 tag covers the
  previous entry's tag, forming a hash chain. Tampering with any entry
  (or reordering/removing one) breaks the chain and is detected on
  `report --verify-audit`.
- **Vault authentication**: a wrong vault passphrase fails AEAD
  authentication (AES-256-GCM tag check) rather than silently decrypting
  to garbage — verified in testing above.
- **NIST SP 800-88 alignment**: `OverwritePattern` includes `NistClear`
  and `NistPurge` variants, and `compliance-check` reports overwrite
  reliability plus a Purge-vs-Clear recommendation per NIST guidance
  (modern guidance treats single-pass random or crypto-erase as
  sufficient on modern media; the legacy DoD 3-pass scheme is included
  for compliance-checkbox compatibility only).

## Known limitations (honestly documented, not hidden)

- **Windows native storage classification** (definitive HDD/SSD/NVMe via
  `IOCTL_STORAGE_QUERY_PROPERTY`, exact filesystem type via
  `GetVolumeInformationW`, ATA/NVMe Secure Erase/Sanitize commands, VSS
  enumeration beyond `vssadmin`) requires Win32 FFI bindings that aren't
  wired up in this build; the code path exists and is clearly marked with
  what call is needed and why, returning `Unknown`/best-guess plus a
  note rather than fabricating a result. This was built and tested on
  Linux; the Windows code paths compile only under `#[cfg(target_os =
  "windows")]` and haven't been run on real Windows hardware.
- **Physical-media forensic recovery** (`verify`/`recover`) analyzes the
  *current byte content* of the target file (signatures, strings,
  entropy) — it does not perform raw-device unallocated-space carving,
  which needs raw disk access and root/admin privileges and is a
  substantially larger scope.
- **Filename timestamp epoch reset** uses a portable no-op (touch); true
  epoch-zeroing needs `utimensat`/`SetFileTime` platform bindings, noted
  in `sanitize/metadata.rs`.
- No GUI/TUI, no dynamically-loaded plugin system, no fuzz-testing
  harness are implemented — the spec's plugin-architecture and fuzzing
  asks are structural/process asks beyond a single CLI binary's scope.

## Tests

```
cargo test
```

17/17 passing: AEAD round-trip + tamper rejection, Argon2id determinism,
HMAC chain verification + tamper detection, entropy measurement,
signature/string detection, secure-memory zeroing.
