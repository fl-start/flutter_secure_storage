# Desktop hardware-backed secure storage architecture

## Goals

1. Consistent envelope encryption for desktop key-value records.
2. Explicit desktop private-key lifecycle with immutable export policy.
3. Accurate capability reporting (hardware private key vs hardware wrapping).
4. Backward-compatible reads of existing Windows / macOS / Linux data.
5. Zero intentional behavior change for Android, iOS, and Web.

## Layers

```text
┌─────────────────────────────────────────────────────────────┐
│ Dart: FlutterSecureStorage + DesktopPrivateKeyManager       │
├─────────────────────────────────────────────────────────────┤
│ Platform interface: errors, capabilities, options, handles  │
├─────────────────────────────────────────────────────────────┤
│ desktop_key_provider │ record_cipher │ record_store │ migrate│
├──────────────┬──────────────────┬───────────────────────────┤
│ Windows      │ macOS (#if only) │ Linux                     │
│ NCrypt/TPM   │ Secure Enclave   │ TPM2 ESAPI (optional)     │
│ DPAPI        │ Keychain / DP    │ Secret Service            │
│ Legacy CNG   │ Software SecKey  │ systemd-creds (optional)  │
│              │                  │ Protected file            │
└──────────────┴──────────────────┴───────────────────────────┘
```

## Envelope encryption (key-value)

```text
Platform protection key (TPM / SE / DPAPI / Secret Service / …)
        │ wraps
        ▼
Data-encryption key (AES-256)
        │ AES-256-GCM
        ▼
Versioned binary record (see record-format.md)
```

Legacy formats remain readable. Successful reads may migrate atomically to the versioned record format; failures leave legacy data intact.

## Asymmetric private keys

```text
Creation-time policy
 ├── nonExportable → key material stays in hardware/keystore; sign/CSR only
 └── exportableEncrypted → software key, encrypted at rest; PKCS#8 export only
```

Exportability is immutable. A non-exportable key never becomes exportable.

Capability reporting always distinguishes:

| Flag | Meaning |
|------|---------|
| `privateKeyHardwareBacked` | Private key resides in hardware/token |
| `storageProtectionHardwareBacked` | Wrapping / DEK protection uses hardware |
| OS-protected software | DPAPI / Keychain / Secret Service without TPM/SE |

An exportable software key wrapped by a TPM/SE key reports:

```text
privateKeyHardwareBacked = false
storageProtectionHardwareBacked = true
exportPolicy = exportableEncrypted
```

## Provider selection

### Windows

| Policy | Selection |
|--------|-----------|
| `platformDefault` | DPAPI user-scope (existing behavior for KV); software CNG for exportable keys |
| `hardwareBackedPreferred` | Platform Crypto Provider (TPM) → DPAPI fallback + `fallbackReason` |
| `hardwareBackedRequired` | Platform Crypto Provider only; fail if unavailable |
| `softwareProtected` | DPAPI / software CNG only |

New device-bound records write under Local AppData. Legacy Roaming / Credential Manager data remains readable.

### macOS

| Policy | Selection |
|--------|-----------|
| `platformDefault` | Data Protection Keychain (existing defaults) |
| `hardwareBackedPreferred` | Secure Enclave → Keychain fallback |
| `hardwareBackedRequired` | Secure Enclave only; **no silent fallback** |
| `softwareProtected` | Keychain without SE requirement |

All new private-key code is `#if os(macOS)`.

### Linux

| Policy | Order |
|--------|-------|
| `platformDefault` | Secret Service → protected file → fail |
| `hardwareBackedPreferred` | TPM2 → Secret Service / systemd-creds → protected file |
| `hardwareBackedRequired` | TPM2 only |
| Headless / service | TPM2 → systemd-creds → protected file (no interactive keyring dependency) |

TPM / systemd are **runtime-optional** (dynamic load). Builds must succeed without TPM development headers when TPM support is disabled or dlopen-based.

## Concurrency

- Atomic temp-file + rename for file backends
- Advisory locks where the OS provides them
- Linux migration away from single JSON must not delete the legacy item until every migrated item is verified
- No AES-GCM nonce reuse with the same key

## Memory

Native paths minimize plaintext lifetime, zero secret buffers on error paths, and never log private keys or passphrases. Dart `String` passphrases have documented erasure limitations; prefer `Uint8List` when practical.
