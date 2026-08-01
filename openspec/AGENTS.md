# Agent guidance — fl-start flutter_secure_storage

This file tells coding agents how to work safely in this repository.

## Read first

1. [project.md](project.md) — product goals and non-goals.
2. Relevant specs under [specs/](specs/) before changing APIs, branching, packaging, or security claims.
3. [DESKTOP_STORAGE.md](../DESKTOP_STORAGE.md) and [docs/architecture/](../docs/architecture/) for implementation detail.

## Hard product rules

- **Production branch is `main`.** Releases and immutable tags SHALL be cut from `main` only.
- **`develop` MUST NEVER be synced with `main`.** Do not merge `main` → `develop`, `develop` → `main` for routine sync, or rewrite `develop` to match `main`. See [specs/branching/spec.md](specs/branching/spec.md).
- **Web is unsupported.** Do not add Web private-key support, Web security guarantees, or marketing language that implies fl-start supports Web.
- **Do not invent private-key APIs.** Public surface is `SecurePrivateKeyStorage` / `DesktopPrivateKeyManager` method names already in tree. Prefer `SecurePrivateKeyStorage.privateKeys`. Compatibility typedef: `DesktopSecureStorage`.
- **Channel name is historical:** `plugins.it_nomads.com/flutter_secure_storage/desktop_keys`. Do not rename casually.
- **Capability honesty:** never set `privateKeyHardwareBacked` / handle `hardwareBacked` true when only wrapping is hardware-backed.
- **No plaintext private-key export.** Prefer `passphraseBytes` over `String passphrase`.
- **Prefer git dependency docs** with `ref: desktop-secure-storage-vX.Y.Z` and `path: flutter_secure_storage`.

## Where code lives

| Concern | Primary locations |
|---------|-------------------|
| App facade | `flutter_secure_storage/lib/` (`secure_private_key_storage.dart`, `desktop/`) |
| Shared desktop types / FSS1 / crypto | `flutter_secure_storage_platform_interface/lib/src/desktop/` |
| Windows keys | `flutter_secure_storage_windows/lib/src/desktop/` |
| Linux keys / systemd-creds / tpm2 | `flutter_secure_storage_linux/lib/src/desktop/` |
| Darwin keys | `flutter_secure_storage_darwin/.../DesktopPrivateKeyManager.swift` |
| Android KV | `flutter_secure_storage/android/` |
| OpenSpec | `openspec/` |

## Change discipline

- Keep diffs focused; do not drive-by reformat unrelated packages.
- Preserve federated plugin boundaries; register platform managers via package `registerWith` / plugin registration.
- When changing export formats, keep dual-read where already implemented (e.g. PKCS#8 PBES2 + legacy FSS-EPK1 decrypt).
- Update OpenSpec + changelogs when behavior or guarantees change.
- Do not invent NCrypt-resident TPM completeness on Windows; document TBD honestly.
- Apple export/CSR today may still use **FSS-EPK1 / FSS-CSR1**; Windows/Linux prefer standards PKCS#8 / PKCS#10 — do not claim Apple already migrated unless code does.

## Testing expectations

- Platform-interface desktop unit tests (FSS1, key id, crypto) MUST stay green for format changes.
- Windows / Linux desktop key manager unit tests for create / sign / export policy / CSR paths touched.
- iOS options regression tests MUST remain green when touching shared Darwin sources.
- Prefer fail-closed tests for `hardwareBackedRequired` and `nonExportable` export refusal.

## What not to do

- Do not push force to `main`.
- Do not move or retag immutable `desktop-secure-storage-v*` tags.
- Do not “fix” `SYNC.md` by re-enabling upstream/`develop` merge as production policy without an explicit OpenSpec change.
- Do not commit secrets, TPM owner passwords, or real export passphrases into the repo.
- Do not weaken diagnostic rules: exception `details` MUST NOT include private keys, passphrases, or plaintext secrets.

## Spec language

OpenSpec requirements use **SHALL / MUST / MUST NOT / SHOULD / MAY**. Treat MUST/SHALL as normative for fl-start production behavior.
