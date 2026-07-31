## 0.3.0

* Added macOS-only `DesktopPrivateKeyManager` (Secure Enclave / Keychain) behind `#if os(macOS)`.
* iOS code paths and option defaults unchanged.

## 0.2.1
- Invalid keychain query parameter combinations are now logged via `NSLog` and surfaced to Dart as a `FlutterError` (`errSecParam`) instead of calling `fatalError`, which crashed the host app.
- Replaced a stray `print` with `NSLog` for access-control creation errors.

## 0.2.0
- Remove keys regardless of synchronizable state or accessibility constraints.

## 0.1.1
 - Fix warnings with Privacy Manifest

## 0.1.0
This package combines flutter_secure_storage_macos together with the ios part of flutter_secure_storage.

Other changes:
- Code has been rebuild from the ground up
- Lots of missing attributes have been added to the IOSOptions and MacOsOptions classes.
