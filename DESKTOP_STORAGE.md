# Desktop secure storage (fl-start fork)

This document describes how `flutter_secure_storage` behaves on **Windows**, **macOS**, and **Linux**, and how to configure it safely.

## Summary

| Platform | Backend | Namespace option | Notes |
|----------|---------|------------------|-------|
| macOS | Keychain (`kSecClassGenericPassword`) | `MacOsOptions.accountName` → `kSecAttrService` | Strongest desktop model; see [docs/macos_entitlements.md](docs/macos_entitlements.md) for sandboxed apps |
| Windows | DPAPI + JSON file | `WindowsOptions.accountName` → separate `.dat` file | User-scoped DPAPI by default |
| Linux | libsecret (GNOME Keyring / KWallet) | `LinuxOptions.accountName` → separate keyring entry | Requires DBus + keyring; one JSON blob per namespace |

## Windows

- All keys for a namespace are stored in one JSON object, encrypted with **DPAPI** (`CryptProtectData` / `CryptUnprotectData`), written under the app support directory as `flutter_secure_storage_<accountName>.dat`.
- **`WindowsOptions.useLocalMachine`**: sets `CRYPTPROTECT_LOCAL_MACHINE`. Use only when you intentionally need **machine-scoped** secrets (e.g. Windows services). Any process with suitable access on that machine may decrypt; this is **not** the default and is weaker for per-user app secrets.
- **`WindowsOptions.useBackwardCompatibility`**: migrates legacy Credential Manager entries. Keep `false` for new apps (required for some key characters).
- **Threat model**: DPAPI binds to the **logged-in Windows user** by default. Malware running as the same user can often read secrets after login. Backups of `%AppData%` copy ciphertext, not plaintext.

## macOS

- Each Flutter key is a separate Keychain item; `accountName` maps to **`kSecAttrService`**.
- **`usesDataProtectionKeychain`** (default `true` on macOS 10.15+) uses the data-protection keychain.
- Optional Secure Enclave path for high-assurance items (`useSecureEnclave`).
- **Threat model**: OS Keychain + login session; sandboxed apps need correct entitlements.

## Linux

- Requires **libsecret** and a running secret service (GNOME Keyring, KWallet, etc.).
- Each `accountName` gets its own libsecret password whose value is a **JSON map of all keys** (read/modify/write rewrites the blob).
- First access may trigger a **keyring unlock** prompt (warmup workaround for libsecret cold-start).
- **`LinuxOptions.accountName`** isolates logical stores (e.g. `secmail.crypto` vs default `flutter_secure_storage_service`).
- **Threat model**: Protection depends on session lock and keyring unlock; processes that can unlock the keyring can read the blob.

## Performance

On **Windows** and **Linux**, `readAll()` decrypts and parses the **entire** namespace. Prefer `read` / `containsKey` for single keys. Consumers such as `secmail_crypto_flutter` maintain a **key index** on those platforms to implement `readAllKeys()` without calling `readAll()`.

## fl-start releases

Tag releases as `v<version>-fl.<n>` (e.g. `v10.0.1-fl.1`) and pin dependents to that tag. See [SYNC.md](SYNC.md) for upstream merge policy.
