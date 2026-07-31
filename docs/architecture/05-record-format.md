# Versioned binary record format (FSS1)

Endianness: little-endian. No native struct padding. Maximum record size: 16 MiB.

## Layout

| Offset | Field | Type | Notes |
|--------|-------|------|-------|
| 0 | magic | 4 bytes | `FSS1` (`0x46 0x53 0x53 0x31`) |
| 4 | format_version | u16 | `1` |
| 6 | provider_id | u16 | See provider table |
| 8 | flags | u32 | bitfield |
| 12 | algorithm_id | u16 | content cipher / key algorithm |
| 14 | reserved | u16 | `0` |
| 16 | key_id_hash | 32 bytes | SHA-256 of normalized key id |
| 48 | created_at | u64 | Unix millis |
| 56 | nonce_len | u16 | |
| 58 | tag_len | u16 | |
| 60 | wrapped_key_len | u32 | |
| 64 | ciphertext_len | u32 | |
| 68 | aad_len | u16 | authenticated additional data |
| 70 | header_crc32 | u32 | CRC32 of bytes `[0,70)` excluding this field (optional integrity) |

Variable section (in order):

1. `nonce` (`nonce_len`)
2. `tag` (`tag_len`)
3. `wrapped_key` (`wrapped_key_len`)
4. `ciphertext` (`ciphertext_len`)
5. `aad` (`aad_len`) — also fed to AES-GCM AAD during decrypt

## Flags (v1)

| Bit | Name |
|-----|------|
| 0 | `machine_scoped` |
| 1 | `hardware_wrapped` |
| 2 | `exportable_private_key` |
| 3 | `user_presence_required` |
| 4 | `migrated_from_legacy` |

## Provider IDs

| ID | Provider |
|----|----------|
| 1 | Windows DPAPI |
| 2 | Windows Platform Crypto (TPM) |
| 3 | Windows Software CNG |
| 4 | macOS Keychain |
| 5 | macOS Secure Enclave |
| 6 | Linux Secret Service |
| 7 | Linux TPM2 |
| 8 | Linux systemd-creds |
| 9 | Linux protected file |

## Parser rules

- Reject truncated buffers
- Reject integer overflows when summing lengths
- Reject `nonce_len == 0` for GCM records
- Reject total size > 16 MiB
- Do not trust filenames as metadata — validate `key_id_hash` against caller key id
- Fuzz-testable pure Dart parser in `desktop_record_format.dart`
