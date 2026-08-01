# Compatibility matrix

## Supported platforms

| Capability | Android | iOS | Windows | macOS | Linux | Web |
|------------|---------|-----|---------|-------|-------|-----|
| KV API | Yes | Yes | Yes | Yes | Yes | **Unsupported** |
| Unified private-key API | Yes (Keystore/StrongBox) | Yes (SE/Keychain) | Yes | Yes (SE/Keychain) | Yes | **Unsupported** |
| FSS1 versioned records | Meta in prefs | Meta in Keychain | Private keys | Meta in Keychain | Private keys (+ file KV) | — |
| Hardware preferred fallback | StrongBox → TEE → software | SE → Keychain | TPM probe → DPAPI | SE → Keychain | TPM2 tools → SS/systemd-creds → file | — |
| Hardware required fail-closed | Yes | Yes | Yes | Yes | Yes | — |
| Exportable encrypted | FSS-EPK1 | FSS-EPK1 | PKCS#8 PBES2 | FSS-EPK1 | PKCS#8 PBES2 | — |
| Non-exportable refuse export | Yes | Yes | Yes | Yes | Yes | — |
| CSR without export | FSS-CSR1 | FSS-CSR1 | PKCS#10 | FSS-CSR1 | PKCS#10 | — |
| Machine scope | Rejected | Rejected | DPAPI LOCAL_MACHINE | Rejected | Rejected | — |
| User presence | Yes (Keystore auth) | Yes | Limited | Yes | No | — |
| Headless | Emulator/CI | Simulator (no SE) | Yes | Limited | Protected file | — |

## Linux distributions (build / runtime)

| Distro | libsecret | TPM2 (optional) | systemd-creds | Protected file |
|--------|-----------|-----------------|---------------|----------------|
| Ubuntu LTS | runtime optional | `tpm2-tools` optional | optional | Yes |
| Debian stable | same | optional | optional | Yes |
| Fedora | optional | optional | optional | Yes |
| openSUSE | optional | optional | optional | Yes |
| Arch | optional | optional | optional | Yes |
| non-systemd / containers | absent OK | optional | absent | Yes |

libsecret and TPM are **not** hard build-time dependencies (soft `dlopen` / CLI probe).

## Branch / distribution

| Item | Policy |
|------|--------|
| Production branch | `main` |
| `develop` | Frozen forever; **never** synced with `main` |
| Primary consume | Git tag `desktop-secure-storage-vX.Y.Z` |
| pub.dev | Packages kept publish-ready; Git until published |
