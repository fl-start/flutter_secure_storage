# Spec: Key-value secure storage

## Purpose

Define requirements for the `FlutterSecureStorage` key-value API on platforms **supported by fl-start**.

## Supported platforms

| Platform | Status |
|----------|--------|
| Android | Supported |
| iOS | Supported |
| Windows | Supported |
| macOS | Supported |
| Linux | Supported |
| **Web** | **OUT OF SCOPE / unsupported by fl-start** |
| Fuchsia | Unsupported |

### Web (normative)

- fl-start **MUST NOT** claim Web as a supported KV platform.
- Presence of `flutter_secure_storage_web` in the monorepo or `platforms: web:` in pubspecs **MUST NOT** be interpreted as a fl-start support guarantee.
- Product documentation and OpenSpec **SHALL** state Web is unsupported.
- Agents and release notes **MUST NOT** market WebCrypto / localStorage behavior as fl-start production storage.

## Public API (normative surface)

The app-facing type is `FlutterSecureStorage`. Implementations SHALL support at least:

| Method | Behavior |
|--------|----------|
| `write({key, value, ...options})` | Persist string value; `value == null` SHALL delete |
| `read({key, ...options})` | Return decrypted string or `null` |
| `containsKey({key, ...options})` | Return whether key exists |
| `delete({key, ...options})` | Remove key; missing key is a no-op |
| `readAll({...options})` | Return all key/value pairs in scope |
| `deleteAll({...options})` | Remove all keys in scope |

Listeners (`registerListener` / unregister helpers) MAY notify Dart observers after write/delete; they MUST NOT weaken storage guarantees.

Platform options types (non-exhaustive): `AndroidOptions`, `IOSOptions` / `AppleOptions`, `MacOsOptions`, `LinuxOptions`, `WindowsOptions`. Web options MAY exist for compile-time federation but are **not** a support commitment.

## Platform backends

### Android

- Storage SHALL use Android Keystore–backed wrapping (RSA OAEP and/or AES-GCM key ciphers per `AndroidOptions`) with encrypted preference/file storage.
- Default storage cipher SHOULD be AES-GCM.
- Biometric / user-presence gating MAY be offered via biometric option constructors and related flags.
- Namespace isolation SHOULD use `storageNamespace` (preferred) over deprecated `sharedPreferencesName`-only isolation.
- Algorithm migration paths that already exist in the Android plugin SHALL remain fail-safe (backup / migrate flags as documented in code).

### iOS

- Storage SHALL use Keychain (`kSecClassGenericPassword` family) with existing iOS option surface.
- Optional Secure Enclave envelope for KV (`useSecureEnclave` / related Apple options) MAY wrap per-item AES keys with an SE-backed key.
- iOS KV behavior MUST remain stable when shared Darwin sources gain macOS-only private-key code (`#if os(macOS)` / equivalent gating).

### macOS

- Storage SHALL use Keychain generic passwords; `MacOsOptions.accountName` (service) SHALL isolate logical stores.
- Optional Secure Enclave envelope for KV MAY be enabled similarly to iOS where implemented.
- Entitlements / Keychain access groups remain app responsibility; see `docs/macos_entitlements.md`.

### Windows

- Default KV backend SHALL encrypt a JSON object with **DPAPI**, stored under app support as `flutter_secure_storage_<accountName>.dat`.
- `WindowsOptions.accountName` SHALL select the file namespace (default `flutter_secure_storage_service`).
- `useLocalMachine` SHALL map to `CRYPTPROTECT_LOCAL_MACHINE` and MUST default to `false` (user-scoped DPAPI).
- `useBackwardCompatibility` MAY migrate legacy Credential Manager / `.secure` (Roaming) into DPAPI JSON; default SHOULD be `false`.
- Legacy `.secure` AES path, when used, SHOULD prefer AES-256-GCM for new writes (AES-128-GCM dual-read as needed for migration).

### Linux

- Preferred desktop path: **Secret Service** via **soft-loaded** `libsecret` (`dlopen` of `libsecret-1.so.0` or equivalent).
- Build MUST NOT hard-require `libsecret-1-dev`.
- Values SHOULD be stored as **one Secret Service item per logical key** after migration from legacy single-JSON blob.
- Legacy JSON item MUST be deleted only after every migrated item is verified.
- `LinuxOptions.accountName` SHALL isolate namespaces.
- When Secret Service / session bus / libsecret is unavailable: protected-file backend under `$XDG_DATA_HOME/<app>/secure-storage/` (or equivalent) with directory mode `0700` and file mode `0600` SHALL be used.
- Optional DEK wrap via `systemd-creds` MAY be used where implemented for private-key / advanced paths; KV protected-file path MUST remain usable headless without systemd-creds.

## Cross-cutting requirements

1. Keys and values for the KV API are **strings** at the Dart boundary.
2. Implementations MUST NOT log secret values.
3. Namespace / account options MUST isolate stores so concurrent logical databases do not clobber each other.
4. Missing keys: `read` returns `null`; `delete` is idempotent.
5. Concurrent access safety is best-effort per OS provider; callers SHOULD serialize critical multi-step updates.
6. Backup / cloud sync behavior follows OS defaults unless options explicitly restrict synchronizable Keychain items (Apple).

## Non-requirements

- Portable ciphertext across devices/browsers (especially irrelevant given Web is unsupported).
- Resistance to same-user malware for software keyring / DPAPI-unlocked secrets (see [security](../security/spec.md)).
- Guaranteeing Web localStorage semantics.
