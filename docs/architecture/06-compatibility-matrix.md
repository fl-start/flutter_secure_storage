# Compatibility matrix

## Desktop platforms

| Capability | Windows | macOS | Linux |
|------------|---------|-------|-------|
| Existing KV API | Yes (DPAPI JSON + legacy CredMan) | Yes (Keychain) | Yes (libsecret JSON → per-item) |
| FSS1 versioned records | Private keys | Private keys | Protected-file / planned KV |
| Hardware preferred fallback | TPM → DPAPI | SE → Keychain | TPM → Secret Service → file |
| Hardware required fail-closed | Yes | Yes | Yes (TPM only) |
| Exportable encrypted PKCS#8 | Yes | Yes | Capabilities exposed; full key ops staged |
| Non-exportable refuse export | Yes | Yes | Yes (policy) |
| CSR without export | Yes (surrogate bundle) | Yes (surrogate bundle) | Planned |
| Machine scope | DPAPI LOCAL_MACHINE | Not for private keys | N/A |
| User presence | Limited | Yes (SE / ACL) | No |
| Headless | Yes | Limited | Protected file / TPM / systemd |

## Linux distributions (build / runtime)

| Distro | libsecret | TPM2 (optional) | systemd-creds | Protected file |
|--------|-----------|-----------------|---------------|----------------|
| Ubuntu LTS | `libsecret-1-dev` / `libsecret-1-0` | `libtss2-dev` (optional) | optional | Yes |
| Debian stable | same | optional | optional | Yes |
| Fedora | `libsecret-devel` | `tpm2-tss-devel` optional | optional | Yes |
| openSUSE | `libsecret-devel` | optional | optional | Yes |
| Arch | `libsecret` | `tpm2-tss` optional | optional | Yes |
| non-systemd | libsecret or none | optional | absent | Yes |

TPM is **not** a hard build-time dependency. Plugin builds without TPM headers; runtime probes `libtss2-esys` when present.

## Mobile

| Platform | Changed? |
|----------|----------|
| Android | No native changes |
| iOS | Shared Darwin sources only; new APIs `#if os(macOS)` gated |
| Web | Untouched |
