# Threat model — desktop secure storage

## Assets

- Application secrets stored via key-value API
- Asymmetric private keys (identity / device / admin)
- Wrapping keys / data-encryption keys
- Export passphrases (transient)

## Trust boundaries

| Boundary | Trust |
|----------|-------|
| OS user session | Partially trusted; malware as same user is in scope as a residual risk |
| TPM / Secure Enclave | Trusted for non-exportable key residence and wrapping |
| Dart isolate / method channel | Untrusted for long-lived secret retention; minimize copies |
| Network / analytics / logs | Never receive secrets |
| Cloud sync (iCloud Keychain) | Disabled for device-bound / SE keys |

## Adversaries

1. **Same-user malware** — can often read DPAPI / unlocked keyring secrets. Hardware-backed non-exportable keys limit extraction; user-presence increases cost.
2. **Root / admin** — can often extract software-protected material; TPM/SE still bound to platform policy.
3. **Physical offline attacker** — without credentials / TPM ownership, ciphertext should remain opaque.
4. **Backup exfiltration** — Local AppData / Keychain dumps yield ciphertext only for properly wrapped records.
5. **Confused deputy / path attacks** — symlink / path traversal via key IDs must fail closed.

## Guarantees

- Non-exportable private keys are never returned as plaintext PKCS#8.
- Exportable keys leave the process only as encrypted PKCS#8 after an explicit export call with a passphrase.
- `hardwareBackedRequired` never silently falls back.
- Capability flags do not claim private-key hardware residence when only wrapping is hardware-backed.
- No embedded global recovery / escrow master key.

## Non-guarantees

- Same-user compromise resistance for software/DPAPI/Secret Service backends
- Survival of TPM keys across owner-clear or PCR-policy mismatch (PCR binding is opt-in)
- Erasure of Dart `String` passphrases from the heap
- Protection after the caller logs or persists an export passphrase

## Platform notes

### Windows

- Default DPAPI is user-scoped; `machineScoped` / `useLocalMachine` widens access intentionally.
- TPM Platform Crypto Provider keys are non-exportable by design.
- Legacy Credential Manager AES keys remain a migration surface.

### macOS

- Secure Enclave keys are device-bound and non-synchronizable.
- Exportable keys are software `SecKey` / CryptoKit material wrapped by SE or Keychain.

### Linux

- Secret Service depends on session unlock.
- Protected-file backend resists casual local users when permissions are correct; it is not root-resistant.
- Filesystem-only master keys require explicit `allowFilesystemOnlyMasterKey`.
