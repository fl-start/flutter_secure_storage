# fl-start fork

Maintained at [github.com/fl-start/flutter_secure_storage](https://github.com/fl-start/flutter_secure_storage).

## Why use this fork

- Pin versions and tags under fl-start control
- Desktop improvements: `LinuxOptions.accountName`, `WindowsOptions.accountName` / `useLocalMachine`
- Documentation: [DESKTOP_STORAGE.md](DESKTOP_STORAGE.md), [docs/macos_entitlements.md](docs/macos_entitlements.md)
- Upstream sync policy: [SYNC.md](SYNC.md)

## Depend on this fork

**Git (CI / releases)** — pin a tag:

```yaml
dependencies:
  flutter_secure_storage:
    git:
      url: https://github.com/fl-start/flutter_secure_storage.git
      ref: v10.0.1-fl.1
      path: flutter_secure_storage
```

**Path (local workspace)**:

```yaml
dependencies:
  flutter_secure_storage:
    path: ../flutter_secure_storage/flutter_secure_storage
```

Use `dependency_overrides` for `flutter_secure_storage_darwin`, `_linux`, `_windows`, `_web`, and `_platform_interface` when not using Melos.

## SecMail

[secmail_crypto_flutter](https://github.com/fl-start/crypto/tree/main/packages/secmail_crypto_flutter) uses namespace `secmail.crypto` on all platforms.
