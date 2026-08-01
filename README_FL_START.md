# fl-start fork

Maintained at [github.com/fl-start/flutter_secure_storage](https://github.com/fl-start/flutter_secure_storage).

**Production branch: `main`.** The `develop` branch is frozen forever and is never synced with `main` — see [SYNC.md](SYNC.md).

## Why use this fork

- Pin versions and tags under fl-start control
- Unified private-key API on **Android, iOS, Windows, macOS, Linux** (`SecurePrivateKeyStorage`)
- Desktop KV improvements: `LinuxOptions.accountName`, `WindowsOptions.accountName` / `useLocalMachine`
- Soft libsecret + TPM2 / systemd-creds paths on Linux; DPAPI + FSS1 on Windows; SE/Keychain on Apple
- Product specs: [openspec/](openspec/)
- Desktop notes: [DESKTOP_STORAGE.md](DESKTOP_STORAGE.md), [docs/macos_entitlements.md](docs/macos_entitlements.md)

## Web is not supported

This fork **does not support Web** for KV or private-key APIs. Do not target `flutter_secure_storage` from this repository in Flutter web apps. Private-key calls throw `unsupportedPlatform` on Web.

## Depend on this fork (Git — primary)

Pin a tag from `main`:

```yaml
dependencies:
  flutter_secure_storage:
    git:
      url: https://github.com/fl-start/flutter_secure_storage.git
      ref: desktop-secure-storage-v11.0.4
      path: flutter_secure_storage
```

Or the fl-start pin tag `v11.0.4-fl.1`.

When Melos workspace packages are not resolved transitively, add `dependency_overrides` for:

- `flutter_secure_storage_platform_interface`
- `flutter_secure_storage_darwin`
- `flutter_secure_storage_linux`
- `flutter_secure_storage_windows`

The `flutter_secure_storage_web` package may remain in the monorepo for historical/upstream reference but is **not** wired into the main plugin (Web unsupported).

**Path (local workspace):**

```yaml
dependencies:
  flutter_secure_storage:
    path: ../flutter_secure_storage/flutter_secure_storage
```

## pub.dev

Packages are kept **pub.dev-ready** (valid pubspecs, changelogs, platforms, analysis). Until a pub.dev publish is performed, **Git tags are the supported distribution channel**.

## Unified private-key API

```dart
import 'package:flutter_secure_storage/secure_private_key_storage.dart';

final keys = SecurePrivateKeyStorage.privateKeys;
if (!SecurePrivateKeyStorage.isSupported) {
  // Web / unsupported
}

final handle = await keys.createPrivateKey(
  DesktopPrivateKeyOptions(
    keyId: 'app.device.identity',
    algorithm: DesktopKeyAlgorithm.ecP256,
    protection: DesktopSecureStorageProtection.hardwareBackedPreferred,
    exportPolicy: PrivateKeyExportPolicy.nonExportable,
  ),
);
```

`DesktopSecureStorage` remains a compatibility typedef for `SecurePrivateKeyStorage`.

## SecMail

[secmail_crypto_flutter](https://github.com/fl-start/crypto/tree/main/packages/secmail_crypto_flutter) uses namespace `secmail.crypto` on all supported platforms.
