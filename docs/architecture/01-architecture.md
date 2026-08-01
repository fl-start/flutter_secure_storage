# Secure storage architecture (fl-start)

## Goals

1. Consistent envelope encryption for key-value records on supported platforms.
2. Unified private-key lifecycle (`SecurePrivateKeyStorage`) with immutable export policy.
3. Accurate capability reporting (hardware private key vs hardware wrapping).
4. Backward-compatible reads of existing Windows / macOS / Linux / mobile KV data.
5. **Web is out of scope** (unsupported).
6. Production on `main` only; `develop` is frozen forever and never synced.

## Layers

```text
┌─────────────────────────────────────────────────────────────┐
│ Dart: FlutterSecureStorage + SecurePrivateKeyStorage        │
├─────────────────────────────────────────────────────────────┤
│ Platform interface: errors, capabilities, options, handles  │
├─────────────────────────────────────────────────────────────┤
│ Providers / keystores / record formats                      │
├──────────┬──────────┬──────────┬──────────┬─────────────────┤
│ Android  │ iOS      │ Windows  │ macOS    │ Linux           │
│ Keystore │ SE / KC  │ DPAPI    │ SE / KC  │ libsecret soft  │
│ StrongBox│ Keychain │ FSS1/TPM │ Keychain │ TPM2 / file     │
└──────────┴──────────┴──────────┴──────────┴─────────────────┘
```

Channel name `.../desktop_keys` is historical and used on all native platforms.

## Envelope encryption (key-value)

```text
Platform protection key (TPM / SE / Keystore / DPAPI / Secret Service / …)
        │ wraps
        ▼
Data-encryption key (AES-256)
        │ AES-256-GCM (or platform equivalent)
        ▼
Versioned / platform record
```

## Asymmetric private keys

```text
Creation-time policy
 ├── nonExportable → key material stays in hardware/keystore; sign/CSR only
 └── exportableEncrypted → software key, encrypted at rest; encrypted export only
```

See [03-api-design.md](03-api-design.md), [06-compatibility-matrix.md](06-compatibility-matrix.md), and [openspec/specs/private-keys/spec.md](../../openspec/specs/private-keys/spec.md).
