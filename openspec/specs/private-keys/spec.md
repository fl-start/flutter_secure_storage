# Spec: Unified private-key API

## Purpose

Define requirements for asymmetric private-key lifecycle across fl-start supported platforms, exposed as **`SecurePrivateKeyStorage`** and implemented through **`DesktopPrivateKeyManager`**.

## Supported platforms

| Platform | Backend (summary) |
|----------|-------------------|
| Android | Android Keystore–backed private keys (unified API) |
| iOS | Secure Enclave / Keychain |
| macOS | Secure Enclave / Keychain |
| Windows | TPM-resident keys via Microsoft Platform Crypto Provider (NCrypt); otherwise DPAPI-wrapped FSS1 + `DesktopCrypto` PKCS#8/PKCS#10 |
| Linux | Soft libsecret / protected-file / systemd-creds wrap + FSS1; TPM2 via `tpm2-tools` |
| **Web** | **OUT OF SCOPE** — always unsupported |

`SecurePrivateKeyStorage.isSupported` MUST be `false` on Web and MUST throw `DesktopSecureStorageErrorCode.unsupportedPlatform` from mutating/query APIs when unsupported.

`isDesktopSupported` MAY remain as a narrower helper (Windows/macOS/Linux only); new code SHOULD prefer `isSupported`.

## Public types (normative names)

Agents and implementations MUST use these names; do not invent parallel APIs.

### Facade

- `SecurePrivateKeyStorage`
- `SecurePrivateKeyStorage.privateKeys` (preferred entry)
- `typedef DesktopSecureStorage = SecurePrivateKeyStorage` (compatibility)

Constructor MAY inject `DesktopPrivateKeyManager?` for tests.

### Manager / channel

- Abstract: `DesktopPrivateKeyManager`
- Default channel impl: `MethodChannelDesktopPrivateKeyManager`
- **Historical channel name (MUST remain):**  
  `plugins.it_nomads.com/flutter_secure_storage/desktop_keys`

Platform packages SHALL register their manager (e.g. `WindowsDesktopKeyManager`, `LinuxDesktopKeyManager`, Darwin Swift `DesktopPrivateKeyManager`) so `DesktopPrivateKeyManager.instance` resolves correctly.

### Methods (exact)

| Method | Notes |
|--------|--------|
| `createPrivateKey(DesktopPrivateKeyOptions options)` | Create under immutable policy |
| `getPrivateKeyHandle(String keyId)` | Metadata handle or `null` |
| `listPrivateKeys()` | Metadata only |
| `getPublicKey(String keyId, {PublicKeyEncoding encoding})` | Default `spkiDer` |
| `sign(String keyId, Uint8List data, {required SignatureAlgorithm algorithm})` | Opaque signing |
| `exportPrivateKey(String keyId, PrivateKeyExportOptions options)` | Encrypted only |
| `importPrivateKey(Uint8List encryptedKey, PrivateKeyImportOptions options)` | Decrypt + re-persist |
| `deletePrivateKey(String keyId)` | Remove key + wrapping companions |
| `getCapabilities({DesktopSecureStorageProtection protection})` | Honest capability snapshot |
| `createCertificateSigningRequest(String keyId, CertificateSigningRequestOptions options)` | No private export required |

Facade methods on `SecurePrivateKeyStorage` SHALL forward to the manager after `_ensureSupported()`.

## Enumerations (normative)

```text
DesktopSecureStorageProtection:
  platformDefault
  hardwareBackedPreferred
  hardwareBackedRequired
  softwareProtected

PrivateKeyExportPolicy:
  nonExportable            # default
  exportableEncrypted      # explicit opt-in

DesktopKeyAlgorithm:
  rsa2048, rsa3072, ecP256, ed25519

PublicKeyEncoding:
  spkiDer, spkiPem

PrivateKeyEncoding:
  pemPkcs8, derPkcs8

PrivateKeyKdf:
  pbkdf2Sha256, argon2id

SignatureAlgorithm:
  rsaPssSha256, rsaPkcs1Sha256, ecdsaSha256, ed25519
```

## Creation options (`DesktopPrivateKeyOptions`)

Fields:

- `keyId` (required) — non-empty, sanitized; namespaced form `app.account.purpose` RECOMMENDED
- `algorithm` (required) — MUST NOT be silently substituted
- `protection` — default `platformDefault`
- `exportPolicy` — default `nonExportable`
- `requireUserPresence` — default `false`
- `machineScoped` — default `false`
- `accountName` — optional namespace
- `metadata` — non-secret only; MUST reject obvious private-key material

Contradictory combinations MUST fail with `invalidConfiguration` or `algorithmUnsupported` (e.g. exportable Ed25519 + `hardwareBackedRequired` where hardware residence is impossible).

Export policy and protection chosen at creation are **immutable** for that `keyId`.

## Handles (`DesktopPrivateKeyHandle`)

Handles MUST be metadata-only (never private key bytes). Required honesty fields:

- `hardwareBacked` — true **only** if the private key itself resides in hardware/token
- `storageProtectionHardwareBacked` — true if wrapping/DEK protection uses hardware (may differ)
- `exportPolicy`, `algorithm`, `provider`, `deviceBound`, `machineScoped`, `userPresenceRequired`

## Export / import

### Export policy enforcement

- `nonExportable`: `exportPrivateKey` MUST fail with `keyNotExportable`.
- `exportableEncrypted`: export MUST return `ExportedPrivateKey` whose `bytes` are **encrypted** (never plaintext PKCS#8 / raw private key).
- Plaintext private-key export MUST NOT exist as an API or channel method.

### Passphrases

- Callers SHOULD prefer `PrivateKeyExportOptions.passphraseBytes` / import `passphraseBytes` (`Uint8List`).
- `String passphrase` MAY be accepted for compatibility but MUST be documented as not reliably wipeable in Dart.
- Empty passphrase MUST fail with `invalidExportPassphrase`.
- Native/mutable buffers SHOULD be zeroed after use; passphrases MUST NOT be persisted.

### Formats by platform (current)

| Platform | On-disk / wrap | Export | CSR |
|----------|----------------|--------|-----|
| Windows | TPM keys: no record (provider key name + public key in `keys.json`); software keys: DPAPI-wrapped **FSS1** via `DesktopCrypto` | Software keys only: standards encrypted PKCS#8 (PBES2); dual-read legacy FSS-EPK1 where implemented. TPM keys are never exportable | PKCS#10 (TPM keys: signed inside the TPM) |
| Linux | FSS1 + Secret Service / protected-file / systemd-creds DEK wrap | Standards encrypted PKCS#8 (PBES2) | PKCS#10 |
| macOS / iOS (Apple) | SE / Keychain | **FSS-EPK1** currently (migration to standards PKCS#8 MAY follow) | **FSS-CSR1** currently (PKCS#10 migration MAY follow) |
| Android | Keystore | Encrypted export only per policy; no plaintext | CSR without export when supported |

Import MUST accept encrypted material consistent with the platform’s supported encodings and re-apply a new immutable policy via `PrivateKeyImportOptions`.

## Capabilities (`DesktopSecureStorageCapabilities`)

`getCapabilities` MUST report at least:

- `platform`, `availableProviders`, `selectedProvider`
- `hardwareAvailable`
- `storageProtectionHardwareBacked`
- `privateKeyHardwareBacked`
- `supportsNonExportableKeys`, `supportsExportableKeys`
- `supportsUserPresence`, `supportsMachineScope`, `supportsCsrGeneration`
- `supportedAlgorithms`, `supportedExportFormats`
- optional `fallbackReason`, `sameUserCompromiseResistant`, `rootCompromiseResistant`

### Honesty rules

1. If only wrapping is hardware-backed, `privateKeyHardwareBacked` MUST be `false`.
2. `hardwareBackedPreferred` MAY fall back and MUST set `fallbackReason` when it does.
3. `hardwareBackedRequired` MUST NOT silently fall back; fail with `hardwareRequiredButUnavailable` (or equivalent typed code).
4. On Windows, handle `hardwareBacked` MUST be `true` only for keys created inside the TPM through the Platform Crypto Provider; software keys stay `false` even when a TPM is present.

## Platform requirements

### Android

- Private keys SHALL be usable through `SecurePrivateKeyStorage` with Android Keystore backing for non-exportable / hardware-oriented policies where the device supports them.
- Exportable keys, when allowed, MUST still leave the API only as encrypted export.
- Biometric / user-presence MAY map to `requireUserPresence` when Keystore auth is available.

### iOS

- Non-exportable keys SHOULD prefer Secure Enclave when protection requests hardware and SE is available.
- Exportable keys MAY be software `SecKey` material wrapped by SE or Keychain.
- Cloud sync for device-bound / SE keys MUST remain disabled / non-synchronizable per security policy.
- Shared Darwin sources MUST NOT break iOS KV when adding private-key paths.

### macOS

- Same SE / Keychain model as Darwin desktop path (`DesktopPrivateKeyManager` Swift).
- `machineScoped` for private keys MUST be rejected if unsupported (`invalidConfiguration`).
- Ed25519 MUST NOT be claimed as SE-resident; unsupported combinations fail closed.
- Current encrypted export/CSR markers: **FSS-EPK1** / **FSS-CSR1**.

### Windows

- TPM availability SHALL come from the Microsoft Platform Crypto Provider reporting a **TPM 2.0** (`PCP_PLATFORM_TYPE`), and SHALL inform `hardwareAvailable`.
- `hardwareBackedRequired` SHALL create the key inside the TPM with `NCryptCreatePersistedKey` / `NCryptFinalizeKey`, export policy `0` and signing-only key usage. The private key MUST NOT exist in process memory or on disk outside the TPM provider's own key blob.
  - Supported: `ecP256`, `rsa2048`; `rsa3072` only where the TPM supports it.
  - MUST fail with `algorithmUnsupported` for `ed25519`, and with `invalidConfiguration` for `exportableEncrypted` or `requireUserPresence`.
  - MUST NOT fall back to software when TPM creation fails.
- `hardwareBackedPreferred` SHALL use the TPM for non-exportable, non-Ed25519 keys without user presence when a TPM is available, and SHALL fall back to a software key when TPM creation fails.
- TPM keys SHALL have a random provider key name (`fss-dsk-<hex>`) recorded in `keys.json`; no FSS1 record is written for them.
- `getPublicKey` for a TPM key SHALL read the public key from the TPM, not from `keys.json`.
- `sign` for a TPM key SHALL sign SHA-256 inside the TPM. ECDSA signatures SHALL be ASN.1 DER, matching software keys; RSA SHALL honour `rsaPssSha256` (salt 32) and otherwise use PKCS#1 v1.5.
- `createCertificateSigningRequest` for a TPM key SHALL build PKCS#10 in Dart and sign it inside the TPM.
- `deletePrivateKey` SHALL delete the key from the TPM before removing its record; a key already gone from the TPM is not an error.
- Software keys: persist as versioned **FSS1** with DPAPI-wrapped DEKs; prefer Local AppData; generation / PKCS#8 / PKCS#10 via shared `DesktopCrypto`.
- `machineScoped` / LOCAL_MACHINE DPAPI (and `NCRYPT_MACHINE_KEY_FLAG` for TPM keys) MUST default off and be explicit when enabled.
- Non-exportable policy MUST refuse export even if material is software-stored.
- Key attestation is not provided; the server cannot yet verify that a reported TPM key is TPM-resident.

### Linux

- Soft-load libsecret; MUST build without hard libsecret link.
- DEK wrap providers MAY include: Secret Service, **systemd-creds**, protected-file.
- Protected-file backend MUST use restrictive permissions; unsafe permissions SHOULD fail with `unsafeFilesystemPermissions` where enforced.
- TPM2-resident create/sign/delete MAY use optional **`tpm2-tools`** CLI (soft dependency); absence + `hardwareBackedRequired` MUST fail closed.
- Direct ESAPI-only private-key path is optional/future; probes MUST NOT claim resident keys without an implemented path.
- Headless: software-protected / protected-file path MUST work without a graphical keyring session.

## Errors

Use `DesktopSecureStorageException` + `DesktopSecureStorageErrorCode`. Diagnostic `details` MUST NEVER include private keys, passphrases, plaintext secrets, or decrypted DEKs.

Notable codes: `providerUnavailable`, `hardwareRequiredButUnavailable`, `algorithmUnsupported`, `keyAlreadyExists`, `keyNotFound`, `keyNotExportable`, `invalidExportPassphrase`, `authenticationRequired`, `authenticationCancelled`, `accessDenied`, `corruptRecord`, `migrationFailed`, `tpmPolicyMismatch`, `keyUnwrapFailed`, `invalidConfiguration`, `unsafeFilesystemPermissions`, `unsupportedPlatform`, `unknown`.

## Record format (desktop)

New desktop private-key blobs SHOULD use **FSS1** (`docs/architecture/05-record-format.md`): magic `FSS1`, embedded `key_id_hash`, flags for machine scope / hardware wrap / exportable / user presence. Filenames MUST NOT be trusted as sole metadata.

## Non-goals

- Web private keys
- Plaintext export helpers
- Silent algorithm substitution
- Windows TPM key attestation (not yet provided)
- Embedding product-wide escrow keys
