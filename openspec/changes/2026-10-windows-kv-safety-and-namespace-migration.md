# Change record: Windows key-value safety and shared-file migration

- **ID:** `2026-10-windows-kv-safety-and-namespace-migration`
- **Date:** 2026-10
- **Status:** Implemented on `main`, pending release tag
- **Packages:** `flutter_secure_storage_windows` 6.0.0
- **Specs touched:** [kv-storage](../specs/kv-storage/spec.md)

## Summary

SecMail carried a vendored copy of `flutter_secure_storage_windows` with fixes this fork lacked. This change brings those fixes here so SecMail can depend on the fork, and adds the migration needed because the vendored copy kept every namespace in one file.

## What changed

- **win32 6:** the package moves to `win32` ^6.0.1 (Dart 3.10, Flutter 3.38). **Breaking** for consumers on older toolchains.
- **Serialized operations:** load/modify/save runs one at a time per plugin instance, so concurrent writes cannot drop keys.
- **Atomic writes:** temp file + rename, keeping the previous good file as `.bak`.
- **No deletion on corruption:** an unreadable file is recovered from `.bak` when possible and moved aside as `.corrupt.<millis>`. Previously the fork deleted it, losing every secret in it.
- **Shared-file migration:** the vendored copy ignored `accountName` and wrote all namespaces into `flutter_secure_storage.dat`. On first run this version snapshots that file (`flutter_secure_storage.legacy-shared.dat`, marker `flutter_secure_storage.namespaces-v2`). Each custom namespace without its own file is seeded once from the snapshot and marked `<file>.seeded`; `deleteAll` keeps the marker. Fresh installs never seed. Seeded namespaces also contain other namespaces' legacy keys; that trade-off was chosen over risking a missed key.
- **No ATL:** the native plugin converts strings with `MultiByteToWideChar` / `WideCharToMultiByte` instead of `atlstr.h`, so builds do not need Visual Studio's ATL component.

## Testing

- `test/unit_test.dart`: existing cases plus migration (seeding, snapshot before default-namespace writes, no re-seed after `deleteAll`, no seeding on fresh install), corrupt-file quarantine with backup recovery, and concurrent writes.
- Native plugin sources compiled with MSVC (ARM64, `/W4`) against the Flutter engine headers.
