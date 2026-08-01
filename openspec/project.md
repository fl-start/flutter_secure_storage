# fl-start / flutter_secure_storage — Project Overview

## Product

**fl-start `flutter_secure_storage`** is a maintained fork of the federated Flutter plugin family `flutter_secure_storage*`. It provides:

1. **Key-value secure storage** via `FlutterSecureStorage` on Android, iOS, Windows, macOS, and Linux.
2. **Unified asymmetric private-key lifecycle** via `SecurePrivateKeyStorage` (compatibility typedef: `DesktopSecureStorage`), backed by `DesktopPrivateKeyManager` and the historical method channel `plugins.it_nomads.com/flutter_secure_storage/desktop_keys`.

Canonical consumption for production dependents (e.g. SecMail):

```yaml
dependencies:
  flutter_secure_storage:
    git:
      url: https://github.com/fl-start/flutter_secure_storage.git
      ref: desktop-secure-storage-v11.0.4
      path: flutter_secure_storage
```

Repository: [github.com/fl-start/flutter_secure_storage](https://github.com/fl-start/flutter_secure_storage).

## Goals

- **Production-grade native storage** for secrets and identity keys on mobile and desktop.
- **Honest security signaling**: capability flags MUST distinguish private-key hardware residence from storage-wrapping hardware.
- **Immutable export policy** at key creation: default `nonExportable`; opt-in `exportableEncrypted` only.
- **No plaintext private-key export**: export SHALL return encrypted material only (PKCS#8 EncryptedPrivateKeyInfo / platform encrypted export).
- **Soft optional native deps on Linux**: `libsecret` via `dlopen`, optional `tpm2-tools`, optional `systemd-creds`, with protected-file fallback for headless environments.
- **Federated package layout** that remains pub.dev-ready while primary distribution is GitHub git refs.
- **Stable release train on `main`** with immutable tags `desktop-secure-storage-vX.Y.Z` and optional pins `vX.Y.Z-fl.1`.

## Non-goals

- **Web support.** Web is **out of scope** for fl-start. The product MUST NOT claim Web as a supported platform for KV or private-key APIs. Callers on Web SHALL receive `unsupportedPlatform` for private-key APIs; KV Web behavior from upstream packages MUST NOT be treated as a fl-start guarantee.
- **Silent hardware fallback when required.** `hardwareBackedRequired` MUST fail closed.
- **Global recovery / escrow master keys.** The product MUST NOT embed a product-wide recovery key.
- **Merging `develop` with `main`.** The long-lived `develop` branch is frozen for fl-start production purposes and MUST NEVER be synced with `main` (see [specs/branching](specs/branching/spec.md)).
- **Upstream `develop` as the production merge source.** fl-start production releases MUST NOT be driven by an “always merge upstream/develop” policy.
- **NCrypt-resident TPM private keys on Windows as a current guarantee.** TPM probe / tools exist; full NCrypt-persisted resident keys are TBD and MUST NOT be advertised as complete.
- **Guaranteeing same-user malware resistance** for software / DPAPI / Secret Service backends.

## Package map

| Package | Role |
|---------|------|
| `flutter_secure_storage` | App-facing facade (`FlutterSecureStorage`, `SecurePrivateKeyStorage`) |
| `flutter_secure_storage_platform_interface` | Platform interface, desktop private-key types, FSS1 codec, `DesktopCrypto` |
| `flutter_secure_storage_darwin` | iOS / macOS Keychain + SE; macOS private-key manager |
| `flutter_secure_storage_linux` | Soft libsecret KV + protected-file; Linux private-key manager |
| `flutter_secure_storage_windows` | DPAPI KV + Windows private-key manager |
| `flutter_secure_storage_web` | Retained in tree historically; not wired into main plugin; **unsupported** |

## Spec index

| Spec | Path |
|------|------|
| Key-value storage | [specs/kv-storage/spec.md](specs/kv-storage/spec.md) |
| Private keys | [specs/private-keys/spec.md](specs/private-keys/spec.md) |
| Branching & releases | [specs/branching/spec.md](specs/branching/spec.md) |
| Packaging & versioning | [specs/packaging/spec.md](specs/packaging/spec.md) |
| Security | [specs/security/spec.md](specs/security/spec.md) |

## Related docs (implementation detail)

- [DESKTOP_STORAGE.md](../DESKTOP_STORAGE.md)
- [docs/architecture/](../docs/architecture/)
- [README_FL_START.md](../README_FL_START.md)
