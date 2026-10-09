# Change record: Windows TPM-resident private keys

- **ID:** `2026-10-windows-tpm-resident-keys`
- **Date:** 2026-10
- **Status:** Implemented on `main`, pending release tag
- **Packages:** `flutter_secure_storage_windows` 5.2.0
- **Specs touched:** [private-keys](../specs/private-keys/spec.md), [project.md](../project.md)

## Summary

Windows private keys that request hardware are now created **inside the TPM** through the Microsoft Platform Crypto Provider instead of being software keys wrapped by DPAPI. This removes the last platform where `nonExportable` was only an API refusal rather than a property of where the key lives.

## Motivation

Consumers (SecMail's license device identity) need a device key that same-user code cannot copy to another machine. On Windows the previous "non-exportable" key was software material in a DPAPI-wrapped file: any process running as the user could unwrap it. Android, iOS, and Apple-silicon macOS already offered hardware-resident keys through the same API.

## What changed

### Behaviour

| Protection | Before | After |
|------------|--------|-------|
| `hardwareBackedRequired` | Software key, DPAPI-wrapped, `hardwareBacked: false`; failed only when no TPM | TPM-resident key, `hardwareBacked: true`; fails closed (no software fallback) |
| `hardwareBackedPreferred` | Software key | TPM-resident key when eligible; software fallback when TPM creation fails |
| `softwareProtected` / `platformDefault` | Software key | Unchanged |

- Eligible for the TPM: `ecP256`, `rsa2048`, `rsa3072` (where the TPM supports it), `nonExportable`, no user presence.
- `hardwareBackedRequired` with `ed25519` → `algorithmUnsupported`; with `exportableEncrypted` or `requireUserPresence` → `invalidConfiguration`.
- Signing hashes with SHA-256 and signs in the TPM. ECDSA output is converted from CNG's `r || s` to ASN.1 DER, so callers see the same format as software keys. RSA honours `rsaPssSha256`.
- CSRs for TPM keys are assembled in Dart (`WindowsDer`) and signed in the TPM.
- `getPublicKey` reads TPM keys' public keys from the TPM, so editing `keys.json` cannot substitute another key.
- TPM detection now requires `PCP_PLATFORM_TYPE` to report `TPM-Version:2.0`; opening the provider alone no longer counts.
- Capabilities for `hardwareBackedRequired` no longer list Ed25519 or exportable keys.

### Storage

TPM keys have no FSS1 record. `keys.json` stores the handle, a cached public key, and the provider key name (`fss-dsk-<32 hex>`, random so apps sharing a Windows user cannot collide). The TPM provider keeps its own key blob under the user's profile.

### Code

- `windows_tpm_key_backend.dart`: `WindowsTpmKeyBackend` interface and `NcryptTpmKeyBackend` (`ncrypt.dll` FFI).
- `windows_der.dart`: SPKI from CNG public blobs, ECDSA re-encoding, PKCS#10 and X.501 name encoding.
- `WindowsDesktopKeyManager` takes an optional `tpmBackend` for tests.

## Testing

- `test/tpm_key_manager_test.dart`: create/sign/CSR/delete/fallback/fail-closed logic against a fake TPM backend, and DER encoding checked byte-for-byte against OpenSSL (SPKI, ECDSA signatures, subject names).
- `test/tpm_real_test.dart`: opt-in (`FSS_TEST_REAL_TPM=1`) run against the machine's TPM; signatures and CSRs are verified with OpenSSL. Passed on Windows 11 ARM64.

## Explicit non-goals

- TPM key attestation (proving to a server that a key is TPM-resident).
- Windows Hello / user-presence prompts for TPM keys.
- Migrating existing software keys into the TPM. Existing keys keep working as software keys; callers that want a TPM key create a new one.
