# Change record: Unified private keys + docs freeze of `develop`

- **ID:** `2026-08-unified-private-keys`
- **Date:** 2026-08
- **Status:** Archived / accepted for fl-start OpenSpec
- **Production branch:** `main`
- **Related tags:** `desktop-secure-storage-v11.0.x`, `v11.0.x-fl.1` (pin train)

## Summary

This change records the fl-start product decision to:

1. Expose a **unified private-key API** (`SecurePrivateKeyStorage` / `DesktopPrivateKeyManager`) across **Android, iOS, Windows, macOS, and Linux**.
2. Keep the historical method channel name `plugins.it_nomads.com/flutter_secure_storage/desktop_keys`.
3. Treat **Web as unsupported**.
4. **Freeze `develop` forever relative to production:** `develop` MUST NEVER be synced with `main`; production releases ship from `main` only.

## Motivation

Desktop private-key work (FSS1, capabilities honesty, export policy) landed on the v11 train. Consumers (including SecMail) need one Dart facade for mobile and desktop identity keys, with explicit platform backends and honest hardware flags. Separately, continuing to treat `develop` as a sync/merge twin of `main` (or as an upstream/`develop` merge treadmill) conflicted with fl-start’s production pin model.

## What changed (product)

### Unified API

- Preferred entry: `SecurePrivateKeyStorage.privateKeys`
- Compatibility: `typedef DesktopSecureStorage = SecurePrivateKeyStorage`
- Methods (normative):  
  `createPrivateKey`, `getPrivateKeyHandle`, `listPrivateKeys`, `getPublicKey`, `sign`, `exportPrivateKey`, `importPrivateKey`, `deletePrivateKey`, `getCapabilities`, `createCertificateSigningRequest`
- Defaults: `PrivateKeyExportPolicy.nonExportable`; encrypted export only; prefer `passphraseBytes`

### Mobile private keys

- **Android:** Android Keystore–backed private-key path behind the unified API (KV Keystore wrapping remains for secrets).
- **iOS:** SE / Keychain private-key path behind the unified API; shared Darwin sources must not regress iOS KV.
- Mobile is in-scope for `SecurePrivateKeyStorage.isSupported` (Web remains false).

### Desktop backends (v11 train)

| Platform | Highlights |
|----------|------------|
| Windows | DPAPI + FSS1; `DesktopCrypto` PKCS#8/PKCS#10; TPM **probe**; NCrypt resident TBD |
| macOS | SE / Keychain; **FSS-EPK1** / **FSS-CSR1** currently |
| Linux | Soft `dlopen` libsecret; protected-file; systemd-creds; tpm2-tools; standards PKCS#8/PKCS#10 |

### Docs / branch policy

- OpenSpec added under `openspec/` as the normative product spec set.
- **`develop`:** exists forever; **MUST NEVER** be synced with `main`.
- **No** upstream `develop` merge policy for fl-start production.
- Releases / tags only from `main`: `desktop-secure-storage-vX.Y.Z` and `vX.Y.Z-fl.1`.

## Explicit non-goals of this change

- Web private keys or Web support guarantees
- Completing Windows NCrypt-resident TPM keys in the same increment
- Migrating Apple FSS-EPK1/FSS-CSR1 to standards PKCS#8/PKCS#10 in the same increment (tracked as follow-up)
- Re-enabling `develop` ↔ `main` sync

## Compatibility

- Existing `FlutterSecureStorage` KV APIs remain the string KV surface.
- Git consumption remains primary, e.g. `ref: desktop-secure-storage-v11.0.4`, `path: flutter_secure_storage`.
- Capability fields continue to separate `privateKeyHardwareBacked` from `storageProtectionHardwareBacked`.

## Follow-ups

- NCrypt-persisted non-exportable TPM private keys on Windows
- Apple migration from FSS-EPK1 / FSS-CSR1 to standards PKCS#8 / PKCS#10
- Direct TPM2 ESAPI path on Linux without requiring `tpm2-tools` for all deployments
- Keep OpenSpec updated when any of the above lands

## Spec references

- [../../specs/private-keys/spec.md](../../specs/private-keys/spec.md)
- [../../specs/branching/spec.md](../../specs/branching/spec.md)
- [../../specs/kv-storage/spec.md](../../specs/kv-storage/spec.md)
- [../../specs/packaging/spec.md](../../specs/packaging/spec.md)
- [../../specs/security/spec.md](../../specs/security/spec.md)
- [../../project.md](../../project.md)
- [../../AGENTS.md](../../AGENTS.md)
