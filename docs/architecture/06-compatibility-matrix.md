# Compatibility matrix

## Desktop platforms

| Capability | Windows | macOS | Linux |
|------------|---------|-------|-------|
| Existing KV API | Yes (DPAPI JSON + legacy CredMan) | Yes (Keychain) | Yes (libsecret JSON → per-item; protected-file fallback) |
| FSS1 versioned records | Private keys | Private keys | Private keys (+ protected-file KV) |
| Hardware preferred fallback | TPM → DPAPI | SE → Keychain | TPM2 tools → SS/systemd-creds → file |
| Hardware required fail-closed | Yes | Yes | Yes (TPM2 tools create/sign when available) |
| Exportable encrypted PKCS#8 | Yes (PBES2) | Yes (FSS-EPK1) | Yes (PBES2) |
| Non-exportable refuse export | Yes | Yes | Yes |
| CSR without export | Yes (PKCS#10) | Yes (FSS-CSR1) | Yes (PKCS#10) |
| Machine scope | DPAPI LOCAL_MACHINE | Not for private keys | N/A (rejected) |
| User presence | Limited | Yes (SE / ACL) | No |
| Headless | Yes | Limited | Protected file (no keyring required) |
| Build without libsecret/TPM headers | N/A | N/A | Yes (soft dlopen) |

## Linux distributions (build / runtime)

| Distro | libsecret | TPM2 (optional) | systemd-creds | Protected file |
|--------|-----------|-----------------|---------------|----------------|
| Ubuntu LTS | runtime optional (`libsecret-1-0`) | `libtss2-esys` optional | optional | Yes |
| Debian stable | same | optional | optional | Yes |
| Fedora | `libsecret` optional | optional | optional | Yes |
| openSUSE | optional | optional | optional | Yes |
| Arch | optional | optional | optional | Yes |
| non-systemd / containers | absent OK | optional | absent | Yes |

TPM is **not** a hard build-time dependency. Plugin builds without TPM headers; runtime probes `libtss2-esys` when present.  
libsecret is **not** a hard build-time dependency. Plugin builds without `libsecret-1-dev`; runtime `dlopen`s `libsecret-1.so.0` when present.

## Mobile

| Platform | Changed? |
|----------|----------|
| Android | No native changes |
| iOS | Shared Darwin sources only; new APIs `#if os(macOS)` gated |
| Web | Untouched |
