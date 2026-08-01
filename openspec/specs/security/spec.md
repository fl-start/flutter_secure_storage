# Spec: Security

## Purpose

Summarize the fl-start threat model and normative rules for capability honesty and hardware vs software signaling.

## Assets

- Application secrets in the KV API
- Asymmetric private keys (identity / device / admin)
- Wrapping keys / DEKs
- Transient export passphrases

## Trust boundaries

| Boundary | Trust posture |
|----------|----------------|
| OS user session | Partially trusted; same-user malware is an in-scope residual risk for software backends |
| TPM / Secure Enclave / Android Keystore strongbox-class hardware | Trusted for non-exportable residence and hardware wrapping when actually used |
| Dart isolate / method channel | Untrusted for long-lived secret retention; minimize copies and lifetime |
| Logs / analytics / crash reporters | MUST NEVER receive secrets, passphrases, or private keys |
| Cloud sync (e.g. iCloud Keychain) | MUST be disabled for device-bound / SE private keys |

## Adversaries (summary)

1. **Same-user malware** — can often read DPAPI / unlocked keyring / software-protected secrets. Hardware-backed **non-exportable** keys limit extraction; user-presence raises cost.
2. **Root / admin** — can often extract software-protected material; hardware policies still bound to platform rules.
3. **Physical offline attacker** — without credentials / TPM ownership, properly wrapped ciphertext SHOULD remain opaque.
4. **Backup exfiltration** — dumps SHOULD yield ciphertext only for correctly wrapped records.
5. **Path / confused-deputy attacks** — malicious `keyId` / path traversal MUST fail closed; do not trust filenames as metadata (FSS1 embeds `key_id_hash`).

## Guarantees (MUST)

1. **No plaintext private-key export.** `exportPrivateKey` returns encrypted material only; `nonExportable` refuses export.
2. **`hardwareBackedRequired` fails closed** — no silent software fallback.
3. **Capability honesty** — see below.
4. **No embedded global recovery / escrow master key.**
5. **Exception diagnostics never include secrets** (`DesktopSecureStorageException.details`).
6. **Web is unsupported** — do not imply browser storage is in the fl-start security boundary.

## Non-guarantees (MUST NOT claim)

- Same-user compromise resistance for DPAPI / Secret Service / protected-file / software Keychain material
- Survival of TPM keys across owner-clear or PCR-policy mismatch (PCR binding is opt-in where present)
- Reliable erasure of Dart `String` passphrases from the heap
- Protection after the caller logs or persists an export passphrase
- Complete Windows **NCrypt-resident** TPM private keys until implemented
- Web / cross-browser portable ciphertext

## Capability honesty (normative)

Implementations MUST distinguish:

| Flag | Meaning |
|------|---------|
| `privateKeyHardwareBacked` / handle `hardwareBacked` | Private key **bytes / signing key** reside in hardware/token |
| `storageProtectionHardwareBacked` | DEK / wrap uses hardware; key itself may still be software |
| `hardwareAvailable` | A hardware provider is detectable / usable for the requested policy |

Rules:

1. Software key + hardware wrap ⇒ `hardwareBacked == false`, `storageProtectionHardwareBacked` MAY be `true`.
2. TPM **probe-only** on Windows without resident key persistence ⇒ MUST NOT set per-key `hardwareBacked` true.
3. `hardwareBackedPreferred` fallback MUST surface `fallbackReason`.
4. Exportable keys MUST NOT be advertised as private-key hardware-resident.
5. `sameUserCompromiseResistant` / `rootCompromiseResistant` MUST stay conservative (default false unless a backend truly warrants otherwise).

### Mental model

| Situation | `privateKeyHardwareBacked` | `storageProtectionHardwareBacked` | Exportable? |
|-----------|----------------------------|-------------------------------------|-------------|
| SE/TPM/Keystore-resident signing key | true | true (typically) | false |
| Software key, hardware wrap | false | true | policy-dependent |
| DPAPI / Keychain / Secret Service / protected-file only | false | false | policy-dependent |

## Passphrase handling

- Prefer `passphraseBytes` (`Uint8List`).
- Zero mutable native buffers after use.
- Never persist export passphrases in KV storage as part of the library.

## Platform notes

### Android

- Keystore-backed keys provide the hardware/non-exportable story when device and options allow.
- EncryptedSharedPreferences legacy paths are migration surfaces, not the long-term security ceiling.

### Apple (iOS / macOS)

- Secure Enclave keys are device-bound and non-synchronizable.
- Exportable keys are software material wrapped by SE or Keychain; current export/CSR may use FSS-EPK1 / FSS-CSR1.

### Windows

- Default DPAPI is user-scoped; `machineScoped` / `useLocalMachine` widens access intentionally.
- Legacy CredMan / `.secure` remain migration surfaces.
- TPM probe informs availability; resident NCrypt keys TBD.

### Linux

- Secret Service depends on session unlock.
- Protected-file resists casual local users when permissions are correct; not root-resistant.
- `tpm2-tools` and `systemd-creds` are optional soft dependencies; fail closed when required hardware path is unavailable.
- Filesystem-only master keys require explicit opt-in where such a flag exists (`allowFilesystemOnlyMasterKey` class controls).

## Related specs

- Private-key API: [../private-keys/spec.md](../private-keys/spec.md)
- KV storage: [../kv-storage/spec.md](../kv-storage/spec.md)
- Implementation threat model detail: [../../docs/architecture/02-threat-model.md](../../../docs/architecture/02-threat-model.md)
