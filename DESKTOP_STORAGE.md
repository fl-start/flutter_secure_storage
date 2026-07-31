# Desktop secure storage (fl-start fork)

This document describes how `flutter_secure_storage` behaves on **Windows**, **macOS**, and **Linux**, including the v11 desktop private-key API.

See also:

- [Architecture](docs/architecture/01-architecture.md)
- [Threat model](docs/architecture/02-threat-model.md)
- [API design](docs/architecture/03-api-design.md)
- [Migration plan](docs/architecture/04-migration-plan.md)
- [Record format](docs/architecture/05-record-format.md)
- [Compatibility matrix](docs/architecture/06-compatibility-matrix.md)

## Summary

| Platform | KV backend | Namespace option | Private keys |
|----------|------------|------------------|--------------|
| macOS | Keychain (`kSecClassGenericPassword`) | `MacOsOptions.accountName` → `kSecAttrService` | SE / Keychain (`#if os(macOS)` only) |
| Windows | DPAPI + JSON file (legacy CredMan + `.secure`) | `WindowsOptions.accountName` | DPAPI-wrapped FSS1 + TPM probe |
| Linux | libsecret per-key items (migrated from JSON blob) | `LinuxOptions.accountName` | Provider matrix + capabilities |

## Key-value storage

### Windows

- Default: JSON object encrypted with **DPAPI**, under app support as `flutter_secure_storage_<accountName>.dat`.
- `useLocalMachine`: `CRYPTPROTECT_LOCAL_MACHINE` (not default).
- `useBackwardCompatibility`: migrates legacy Credential Manager / `.secure` (Roaming) into DPAPI JSON.
- New private-key records prefer **Local AppData**.

### macOS

- Each Flutter key is a separate Keychain item; optional Secure Enclave envelope for KV (`useSecureEnclave`).
- **iOS behavior is unchanged.** New private-key code is macOS-gated.

### Linux

- Secret Service via libsecret.
- After upgrade, values migrate from a single JSON secret to **one secret per logical key**.
- Legacy JSON item is deleted only after every migrated item is verified.
- Fallback: protected encrypted-file backend under `$XDG_DATA_HOME/<app>/secure-storage/` (mode `0700`/`0600`).
- TPM2 / systemd-creds are optional runtime providers (not required to build).

## Desktop private-key API

```dart
import 'package:flutter_secure_storage/desktop/desktop_secure_storage.dart';

final storage = DesktopSecureStorage.privateKeys;

// Non-exportable admin key
final handle = await storage.createPrivateKey(
  DesktopPrivateKeyOptions(
    keyId: 'idr.admin.identity',
    algorithm: DesktopKeyAlgorithm.ecP256,
    protection: DesktopSecureStorageProtection.hardwareBackedRequired,
    exportPolicy: PrivateKeyExportPolicy.nonExportable,
    requireUserPresence: true,
  ),
);

// Exportable device key
final device = await storage.createPrivateKey(
  DesktopPrivateKeyOptions(
    keyId: 'idr.device.identity',
    algorithm: DesktopKeyAlgorithm.ecP256,
    protection: DesktopSecureStorageProtection.hardwareBackedPreferred,
    exportPolicy: PrivateKeyExportPolicy.exportableEncrypted,
  ),
);

final exported = await storage.exportPrivateKey(
  'idr.device.identity',
  PrivateKeyExportOptions(
    encoding: PrivateKeyEncoding.pemPkcs8,
    passphrase: exportPassphrase,
    kdf: PrivateKeyKdf.pbkdf2Sha256,
  ),
);
// exported.bytes remain encrypted PKCS#8
```

### Export vs hardware

| Situation | `privateKeyHardwareBacked` | `storageProtectionHardwareBacked` | exportable |
|-----------|----------------------------|-----------------------------------|------------|
| SE/TPM-resident signing key | true | true | false |
| Software key, SE/TPM wrap | false | true | true |
| DPAPI / Keychain / Secret Service only | false | false | policy-dependent |

### Passphrases

Prefer `passphraseBytes` (`Uint8List`). Dart `String` passphrases cannot be reliably wiped from memory.

## Threat model (short)

- Same-user malware can often read software-protected secrets after login.
- Hardware-backed non-exportable keys resist extraction; export is rejected.
- No embedded global recovery / escrow key.
- Filenames are never trusted metadata (FSS1 embeds `key_id_hash`).

## fl-start releases

- Package version **11.0.0**
- Immutable production tag: `desktop-secure-storage-v11.0.0` on `main`
- Optional pin: `v11.0.0-fl.1` (see `SYNC.md`)
