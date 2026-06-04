# macOS Keychain entitlements

`flutter_secure_storage` on macOS uses the **Keychain** via `flutter_secure_storage_darwin`. Sandboxed Mac apps must declare access or Keychain operations fail with Security framework errors surfaced as `PlatformException`.

## App Sandbox

If **App Sandbox** is enabled in Xcode:

1. Open **Signing & Capabilities** for your macOS runner target.
2. Add **Keychain Sharing** if you use `MacOsOptions.groupId` / app groups.
3. For a single-app store, the default Keychain access group is usually sufficient without a custom group.

## Hardened Runtime

Distribution outside the Mac App Store may require **Hardened Runtime**. Keychain access is still allowed; biometric-gated items may prompt the user.

## Options that affect prompts

| Option | Effect |
|--------|--------|
| `accessibility` | When items are readable (e.g. after first unlock) |
| `accessControlFlags` | Biometry / passcode requirements |
| `useSecureEnclave` | Secure Enclave–backed encryption path |

## Debugging failures

- Inspect `PlatformException.message` for `errSec*` codes.
- Use **Keychain Access.app** → search by service name (`MacOsOptions.accountName`, default `flutter_secure_storage_service`).
- For SecMail, use a dedicated namespace: `MacOsOptions(accountName: 'secmail.crypto')`.

## Related

See [DESKTOP_STORAGE.md](../DESKTOP_STORAGE.md) for cross-platform behavior.
