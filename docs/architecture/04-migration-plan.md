# Migration plan

## Principles

1. Read old formats forever (or until a documented sunset).
2. Write new versioned records for new data and successful migrations.
3. Atomic migrate: temp → fsync → rename → verify → only then delete obsolete material.
4. Interrupted migration is recoverable; never destroy old data on failure.
5. Do not change mobile formats.

## Windows

| Legacy | Detection | Target |
|--------|-----------|--------|
| DPAPI JSON (`flutter_secure_storage.dat` / namespaced `.dat`) | File magic absent; DPAPI unwrap → JSON map | Per-key FSS1 records under Local AppData (optional migrate-on-read) |
| Credential Manager + `.secure` (Roaming) | `useBackwardCompatibility` / presence of prefixed creds | Existing path already migrates into DPAPI JSON; then optional FSS1 |
| AES-128 DEK in CredMan (`key_*`, 16 bytes) | Size 16 blob | New AES-256 DEK in CredMan (`key256_*`); rewrite `.secure` on successful legacy read |
| AES-256 DEK in CredMan (`key256_*`) | Size 32 blob | Current write path (AES-256-GCM) |

Default KV behavior remains DPAPI JSON for compatibility unless apps opt into the new record store. New private-key material always uses versioned records + Local AppData.

## macOS

| Legacy | Action |
|--------|--------|
| Generic password items | Continue to work unchanged |
| `fss.enclave.*` / `fss.wrapped.*` | Continue for KV Secure Enclave path |
| New private keys | Separate Keychain key class / tags under `fss.dsk.*` namespace |

iOS paths untouched.

## Linux

| Legacy | Action |
|--------|--------|
| Single JSON secret per `accountName` | On first write/read-all with new backend: expand to per-key Secret Service items with attributes `application-id`, `account-name`, `storage-key-hash`, `record-version` |
| Delete legacy JSON | Only after every key verified in item store |
| Concurrent writers | File lock / migrate marker item `migration-in-progress` |

Protected-file and TPM backends are new; no legacy records there.

## Versioning

Record magic `FSS1` (ASCII), `format_version` uint16 little-endian starting at `1`.

Unknown future versions: reject with `corruptRecord` / forward-compatible skip only when explicitly marked with supported feature flags.
