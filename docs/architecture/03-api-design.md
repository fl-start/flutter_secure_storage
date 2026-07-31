# Desktop private-key API design

## Principles

- Additive: existing `FlutterSecureStorage` key-value methods are unchanged.
- Opaque handles: never return raw private-key bytes except via encrypted export.
- Policy at creation time: protection + export policy are immutable.
- Accurate capabilities: separate private-key hardware from storage wrapping hardware.
- Desktop-only: mobile platforms throw `unsupportedPlatform` for these APIs.

## Enums

```dart
enum DesktopSecureStorageProtection {
  platformDefault,
  hardwareBackedPreferred,
  hardwareBackedRequired,
  softwareProtected,
}

enum PrivateKeyExportPolicy {
  nonExportable,       // default
  exportableEncrypted, // explicit opt-in
}

enum DesktopKeyAlgorithm { rsa2048, rsa3072, ecP256, ed25519 }

enum PrivateKeyEncoding { pemPkcs8, derPkcs8 }

enum PrivateKeyKdf { pbkdf2Sha256, argon2id }

enum SignatureAlgorithm {
  rsaPssSha256,
  rsaPkcs1Sha256,
  ecdsaSha256,
  ed25519,
}

enum PublicKeyEncoding { spkiDer, spkiPem }
```

## Types

See `flutter_secure_storage_platform_interface` desktop library:

- `DesktopPrivateKeyOptions`
- `DesktopPrivateKeyHandle`
- `PrivateKeyExportOptions` / `ExportedPrivateKey`
- `PrivateKeyImportOptions` / `ImportedPrivateKey`
- `CertificateSigningRequestOptions`
- `DesktopSecureStorageCapabilities`
- `DesktopSecureStorageException` + `DesktopSecureStorageErrorCode`

## Operations

| Method | Notes |
|--------|-------|
| `createPrivateKey` | Rejects contradictory options; no algorithm substitution |
| `getPrivateKeyHandle` / `listPrivateKeys` | Metadata only |
| `getPublicKey` | SPKI |
| `sign` | Via opaque handle |
| `exportPrivateKey` | Encrypted PKCS#8; fails with `keyNotExportable` |
| `importPrivateKey` | Decrypts PKCS#8, re-persists under new policy |
| `deletePrivateKey` | Removes key + companion wrapping records |
| `createCertificateSigningRequest` | No export required |
| `getCapabilities` | Provider inventory + algorithm matrix |

## Validation rules

- `keyId` must be non-empty, namespaced (`app.account.purpose` recommended), sanitized before native IDs / filenames.
- `machineScoped` defaults to `false`.
- `requireUserPresence` incompatible with unattended service defaults (caller responsibility; may fail with `authenticationRequired`).
- `exportableEncrypted` + `hardwareBackedRequired` is valid only when wrapping can be hardware-backed while the private key remains software — never claim private-key hardware residence.
- Metadata must not contain private-key material (best-effort validation).

## Passphrase handling

Prefer `Uint8List passphraseBytes`. If `String passphrase` is used, document that Dart strings are immutable and cannot be reliably wiped. Native code zeros mutable buffers after use and does not persist the passphrase.
