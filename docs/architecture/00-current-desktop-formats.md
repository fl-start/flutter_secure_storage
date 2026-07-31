# Current desktop storage formats (baseline)

Inspection baseline for `feature/desktop-hardware-backed-storage`, derived from `develop` at the branch cut.

## Package versions (pre-change)

| Package | Version |
|---------|---------|
| `flutter_secure_storage` | 10.0.1 |
| `flutter_secure_storage_platform_interface` | 2.0.2 |
| `flutter_secure_storage_windows` | 4.1.1 |
| `flutter_secure_storage_darwin` | 0.2.1 |
| `flutter_secure_storage_linux` | 3.0.1 |

fl-start release tag convention: `v10.0.1-fl.1` (see `SYNC.md`).

## Windows

### Active path (Dart FFI)

- Implementation: `flutter_secure_storage_windows/lib/src/flutter_secure_storage_windows_ffi.dart`
- Protection: DPAPI (`CryptProtectData` / `CryptUnprotectData`)
- Default scope: user (`dpapiFlags = 0`); optional machine via `WindowsOptions.useLocalMachine` → `CRYPTPROTECT_LOCAL_MACHINE`
- Layout: one JSON object of all keys, encrypted as a single blob
- Path: application support directory (`path_provider`) +
  - default namespace → `flutter_secure_storage.dat`
  - custom `accountName` → `flutter_secure_storage_<sanitized>.dat`
- Namespace option: `WindowsOptions.accountName` (default `flutter_secure_storage_service`)

### Legacy path (C++ plugin / Credential Manager)

- Implementation: `flutter_secure_storage_windows/windows/flutter_secure_storage_windows_plugin.cpp`
- AES-256 key (32 bytes) in Windows Credential Manager as `key256_*` (`CredReadW` / `CredWriteW`)
- Legacy AES-128 key (16 bytes) under `key_*` remains readable for migration
- Values: AES-256-GCM (BCrypt) files under **Roaming** AppData (`FOLDERID_RoamingAppData`)
- File pattern: prefixed keys + `.secure` ciphertext (nonce + tag + ciphertext)
- Migration: `useBackwardCompatibility: true` copies legacy entries into the DPAPI JSON file (default namespace only)

## macOS / iOS (Darwin shared sources)

Shared Swift sources under:

```text
flutter_secure_storage_darwin/darwin/.../FlutterSecureStorage.swift
flutter_secure_storage_darwin/darwin/.../FlutterSecureStorageDarwinPlugin.swift
```

Both iOS and macOS use `sharedDarwinSource: true`.

### Key-value storage

- Class: `kSecClassGenericPassword`
- Service: `accountName` → `kSecAttrService`
- Optional Data Protection Keychain on macOS (`kSecUseDataProtectionKeychain`, `#if os(macOS)`)
- Optional Secure Enclave envelope (`useSecureEnclave`):
  - SE EC key tag: `fss.enclave.<service>`
  - Per-item AES-256-GCM payload in Keychain
  - Companion wrapped AES key account: `fss.wrapped.<key>`
  - Wrap algorithm: ECIES cofactor X9.63 SHA-256 AES-GCM

### Darwin / iOS risk

Any change to shared Swift without `#if os(macOS)` guards can alter iOS behavior. New desktop private-key APIs must be macOS-gated. Existing iOS option serialization and Secure Enclave fallbacks must remain unchanged.

## Linux

- Implementation: `flutter_secure_storage_linux/linux/flutter_secure_storage_linux_plugin.cc` + `include/Secret.hpp` + soft `secret_service_loader` + `ProtectedFileProvider`
- Backend: libsecret via **dlopen** (per-key items + legacy JSON migration); protected-file fallback under `$XDG_DATA_HOME`
- Schema attribute: `account` = `<APPLICATION_ID>.<accountName>.secureStorage`
- Namespace: `LinuxOptions.accountName`
- Private keys: Dart `LinuxDesktopKeyManager` (FSS1 / FSS-EPK1 / FSS-CSR1); DEK wrap via Secret Service or protected-file
- TPM2 ESAPI: runtime probe only (`libtss2-esys`); not required to build

## Private-key management

Desktop API on Windows / macOS / Linux via `DesktopPrivateKeyManager` (see `DESKTOP_STORAGE.md`).

## CI (baseline)

- `.github/workflows/ci.yml`: analysis, format, unit tests, Android/iOS/Web integration; triggers on `master` and `develop`
- `.github/workflows/desktop-smoke.yml`: Windows/Linux unit tests, Linux builds with and without libsecret-dev, macOS example build
