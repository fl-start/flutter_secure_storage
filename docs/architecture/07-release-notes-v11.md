# Release notes — desktop-secure-storage-v11.0.0

## Highlights

- Desktop private-key API with immutable export policy (`nonExportable` default).
- Capability reporting separates `privateKeyHardwareBacked` from `storageProtectionHardwareBacked`.
- Versioned FSS1 binary record format with fuzz-tested Dart parser.
- Windows: DPAPI-wrapped software keys, TPM probe via Platform Crypto Provider, Local AppData private-key store.
- macOS: Secure Enclave non-exportable keys and software exportable keys with SE/Keychain wrapping (`#if os(macOS)` only).
- Linux: per-key Secret Service items with legacy JSON migration; protected-file provider; optional TPM/systemd slots.

## Breaking / major

- Package major bump to **11.0.0** for the new desktop key-management surface.
- Existing key-value APIs remain compatible.

## Tagging

- Production branch: `main`
- Immutable tag: `desktop-secure-storage-v11.0.0`
- fl-start pin (optional): `v11.0.0-fl.1`
