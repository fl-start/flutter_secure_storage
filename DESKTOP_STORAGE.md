# Secure storage (fl-start fork)

This document describes how `flutter_secure_storage` behaves on **supported native platforms**, including the unified private-key API.

**Web is not supported** by this fork.

See also:

- [OpenSpec](openspec/project.md)
- [Architecture](docs/architecture/01-architecture.md)
- [Threat model](docs/architecture/02-threat-model.md)
- [API design](docs/architecture/03-api-design.md)
- [Compatibility matrix](docs/architecture/06-compatibility-matrix.md)
- [Branch policy](SYNC.md)

## Summary

| Platform | KV backend | Namespace option | Private keys |
|----------|------------|------------------|--------------|
| Android | EncryptedSharedPreferences / Keystore wrap | `AndroidOptions` | Android Keystore / StrongBox + software exportable |
| iOS | Keychain (+ optional SE wrap) | `IOSOptions.accountName` | Secure Enclave / Keychain |
| macOS | Keychain (+ optional SE wrap) | `MacOsOptions.accountName` | Secure Enclave / Keychain |
| Windows | DPAPI + JSON (legacy CredMan + AES-256-GCM `.secure`) | `WindowsOptions.accountName` | DPAPI-wrapped FSS1 + TPM probe |
| Linux | Soft-loaded libsecret + protected-file / systemd-creds | `LinuxOptions.accountName` | FSS1 + PKCS#8/PKCS#10; TPM2 tools |
| Web | — | — | **Unsupported** |

## Key-value storage

### Windows

- Default: JSON object encrypted with **DPAPI**, under app support as `flutter_secure_storage_<accountName>.dat`.
- `useLocalMachine`: `CRYPTPROTECT_LOCAL_MACHINE` (not default).
- `useBackwardCompatibility`: migrates legacy Credential Manager / `.secure` (Roaming) into DPAPI JSON.
- New private-key records prefer **Local AppData**.

### macOS / iOS

- Each Flutter key is a separate Keychain item; optional Secure Enclave envelope for KV (`useSecureEnclave`).
- Private-key API is available on **both** iOS and macOS via the Darwin package.

### Linux

- Secret Service via **soft-loaded** libsecret (`dlopen`); builds do not require `libsecret-1-dev`.
- After upgrade, values migrate from a single JSON secret to **one secret per logical key**.
- Headless / no session bus / missing libsecret: protected-file backend under `$XDG_DATA_HOME/<app>/secure-storage/` (mode `0700`/`0600`).
- Private keys: Dart `LinuxDesktopKeyManager` with FSS1 records, standards PKCS#8 PBES2 export/import, PKCS#10 CSR.
- DEK wrap via Secret Service, systemd-creds, or protected-file.
- TPM2-resident keys via optional `tpm2-tools` when hardware is required/preferred.

### Android

- Existing encrypted preferences / Keystore wrapping for KV unchanged.
- Private keys use a separate Keystore alias namespace (`*.fss.dsk.*`).

## Unified private-key API

```dart
import 'package:flutter_secure_storage/secure_private_key_storage.dart';

final storage = SecurePrivateKeyStorage.privateKeys;
// DesktopSecureStorage is a typedef alias for SecurePrivateKeyStorage.

final handle = await storage.createPrivateKey(
  DesktopPrivateKeyOptions(
    keyId: 'idr.admin.identity',
    algorithm: DesktopKeyAlgorithm.ecP256,
    protection: DesktopSecureStorageProtection.hardwareBackedRequired,
    exportPolicy: PrivateKeyExportPolicy.nonExportable,
    requireUserPresence: true,
  ),
);

final exported = await storage.exportPrivateKey(
  'idr.device.identity',
  PrivateKeyExportOptions(
    encoding: PrivateKeyEncoding.pemPkcs8,
    passphraseBytes: exportPassphraseBytes, // preferred over String
    kdf: PrivateKeyKdf.pbkdf2Sha256,
  ),
);
```

The method channel name `.../desktop_keys` is historical and shared by all native platforms.

### Export vs hardware

| Situation | `privateKeyHardwareBacked` | `storageProtectionHardwareBacked` | exportable |
|-----------|----------------------------|-----------------------------------|------------|
| SE/TPM/Keystore-resident signing key | true | true | false |
| Software key, SE/TPM/Keystore wrap | false | true | true |
| Software / DPAPI / Keychain / Secret Service only | false | false | policy-dependent |

### Passphrases

Prefer `passphraseBytes` (`Uint8List`). Dart `String` passphrases cannot be reliably wiped from memory.

### Format notes

| Platform | Export / CSR |
|----------|----------------|
| Linux / Windows | PKCS#8 PBES2 + PKCS#10 (via `DesktopCrypto`) |
| Android / iOS / macOS | FSS-EPK1 encrypted export + FSS-CSR1 (Apple/Android channel path) |

## Threat model (short)

- Same-user malware can often read software-protected secrets after login.
- Hardware-backed non-exportable keys resist extraction; export is rejected.
- No embedded global recovery / escrow key.
- Filenames are never trusted metadata (FSS1 embeds `key_id_hash`).

## fl-start releases

- Package version **11.0.4**
- Immutable production tag: `desktop-secure-storage-v11.0.4` on `main`
- Optional pin: `v11.0.4-fl.1` (see `SYNC.md`)
- `develop` is never synced with `main`
