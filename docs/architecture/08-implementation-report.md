# Implementation report — desktop-secure-storage-v11.0.0

## Files changed (high level)

- `docs/architecture/*` — architecture, threat model, API, migration, record format, matrix, release notes
- `DESKTOP_STORAGE.md` — desktop user documentation
- `flutter_secure_storage_platform_interface/lib/src/desktop/*` — shared Dart API + FSS1 codec
- `flutter_secure_storage/lib/desktop/desktop_secure_storage.dart` — facade
- `flutter_secure_storage_windows/lib/src/desktop/windows_desktop_key_manager.dart`
- `flutter_secure_storage_darwin/.../DesktopPrivateKeyManager.swift` (`#if os(macOS)`)
- `flutter_secure_storage_darwin/.../FlutterSecureStorageDarwinPlugin.swift` — macOS desktop_keys channel
- `flutter_secure_storage_linux/linux/include/Secret.hpp` — per-key Secret Service + migration
- `flutter_secure_storage_linux/linux/include/providers/*` — provider interface + protected file
- `.github/workflows/ci.yml`, `desktop-smoke.yml`
- Package versions / changelogs

## Public APIs added

- `DesktopSecureStorageProtection`, `PrivateKeyExportPolicy`, `DesktopKeyAlgorithm`, …
- `DesktopPrivateKeyOptions`, `DesktopPrivateKeyHandle`
- `DesktopPrivateKeyManager` / `DesktopSecureStorage`
- `DesktopSecureStorageCapabilities`, `DesktopSecureStorageException`
- `DesktopRecordCodec` (FSS1)

## Native APIs used

- Windows: DPAPI (`CryptProtectData`/`UnprotectData`), `ncrypt.dll` probe (`NCryptOpenStorageProvider`), existing BCrypt/CredMan legacy path retained
- macOS: Security.framework `SecKey` + Secure Enclave, CryptoKit AES-GCM, CommonCrypto PBKDF2, Data Protection Keychain
- Linux: libsecret per-item store; protected-file `open`/`fsync`/`rename`; TPM/systemd optional slots

## Dependencies added

- Windows: `pointycastle` ^3.9.1 (software key generation / AES-GCM) — BSD-3-Clause, desktop-only package impact

## Legacy formats supported

- Windows DPAPI JSON `.dat`
- Windows Credential Manager + `.secure` (via existing backward compatibility)
- macOS Keychain generic passwords + existing SE envelope KV
- Linux single-JSON libsecret item (migrated to per-key)

## Migration behavior

- Atomic where file-backed (temp + rename + verify)
- Linux: legacy JSON retained until every key verified in v2 items
- Failures leave legacy data intact

## Security fallbacks

- `hardwareBackedPreferred` reports `fallbackReason`
- `hardwareBackedRequired` fails closed
- Exportable keys never claim private-key hardware residence

## Unsupported combinations

- Ed25519 + hardwareBackedRequired (TPM/SE)
- macOS `machineScoped` private keys
- Full standards PKCS#8 ASN.1 import round-trip staged on Windows
- Physical TPM integration tests in CI (reported separately)

## Tests executed / skipped

See CI / local test run summary in the PR. Expected:

| Suite | Status intent |
|-------|----------------|
| FSS1 / key-id unit tests | run |
| Windows desktop key unit tests (mocked TPM) | run |
| iOS options regression | run |
| Linux/macOS example builds | run |
| Physical TPM integration | skipped / not available |

## Known limitations

- Windows non-exportable “hardware” path currently probes TPM and stores software material with accurate export refusal; full NCrypt persisted non-exportable keys are the next hardening step.
- Linux private-key create/sign/export is implemented (software keys + SS/file DEK wrap); TPM-resident private keys remain future work (`hardwareBackedRequired` fails closed).
- CSR payloads use an internal `FSS-CSR1` bundle pending full PKCS#10 ASN.1.
- Dart `String` export passphrases cannot be wiped.

## Release commit / tag

- Release commit: `0bed61cd72007af7ce96e5c6fb117f23b509f598` (on `main` and feature branch)
- Release tag: `desktop-secure-storage-v11.0.0`
- fl-start pin tag: `v11.0.0-fl.1`
- Feature PR into develop: https://github.com/fl-start/flutter_secure_storage/pull/1

## Tests executed (local)

| Suite | Result |
|-------|--------|
| platform_interface `test/desktop` | passed |
| windows package `flutter test` | passed |
| main package unit + iOS options regression | passed |
| Physical TPM integration | not available / skipped |
| Linux/macOS example builds | CI Desktop Smoke |

## Known follow-ups

- Full NCrypt-persisted non-exportable TPM private keys on Windows
- Linux TPM2-resident private-key create/sign (beyond probe + fail-closed)
- Standards-complete PKCS#10 CSR encoding
- Sync `develop` with `main` release history
