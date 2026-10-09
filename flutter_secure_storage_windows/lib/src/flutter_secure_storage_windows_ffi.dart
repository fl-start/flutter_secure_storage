import 'dart:async';
import 'dart:convert';
import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter/foundation.dart'
    show debugPrint, kDebugMode, visibleForTesting;
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:flutter_secure_storage_platform_interface/flutter_secure_storage_platform_interface.dart';
import 'package:flutter_secure_storage_windows/src/desktop/windows_desktop_key_manager.dart';
import 'package:path/path.dart' as path;
import 'package:path_provider/path_provider.dart';
import 'package:win32/win32.dart';

/// An extension on `Map<String, String>` to add support for specific
/// configuration options related to backward compatibility.
@visibleForTesting
extension OptionsExtension on Map<String, String> {
  /// Checks whether the `useBackwardCompatibility` flag is enabled in the map.
  ///
  /// Returns:
  /// - `true` if the value associated with the `useBackwardCompatibility` key
  ///   is not `'false'`.
  /// - `false` otherwise.
  bool get useBackwardCompatibility =>
      this['useBackwardCompatibility'] != 'false';

  /// DPAPI scope: machine-wide when `useLocalMachine` is `'true'`.
  bool get useLocalMachine => this['useLocalMachine'] == 'true';

  /// Win32 `CRYPTPROTECT_LOCAL_MACHINE` (0x4).
  int get dpapiFlags => useLocalMachine ? 0x4 : 0;

  /// Namespace for the on-disk JSON file (see [encryptedJsonFileName]).
  String get accountName => this['accountName'] ?? defaultWindowsAccountName;

  /// Legacy Credential Manager entries were never namespaced, so migration is
  /// only safe for the default namespace. Enabling `useBackwardCompatibility`
  /// on a custom [accountName] is ignored (otherwise legacy values would leak
  /// into whichever namespace read them first).
  bool get legacyMigrationEnabled {
    if (!useBackwardCompatibility) {
      return false;
    }
    if (accountName != defaultWindowsAccountName) {
      if (kDebugMode) {
        debugPrint(
          'flutter_secure_storage: useBackwardCompatibility is ignored for '
          'accountName "$accountName"; legacy migration only runs for the '
          'default namespace ("$defaultWindowsAccountName").',
        );
      }
      return false;
    }
    return true;
  }
}

/// Default Windows namespace; matches `WindowsOptions.defaultAccountName`.
@visibleForTesting
const String defaultWindowsAccountName = 'flutter_secure_storage_service';

/// The `FlutterSecureStorageWindows` class provides a Windows-specific
/// implementation of the `FlutterSecureStoragePlatform` interface.
///
/// This implementation uses a combination of a backward-compatible storage
/// mechanism and a platform-specific storage backend.
class FlutterSecureStorageWindows extends FlutterSecureStoragePlatform {
  /// Creates an instance of `FlutterSecureStorageWindows` with default
  /// configurations for both backward compatibility and platform-specific
  /// storage.
  FlutterSecureStorageWindows()
      : this._(
          MethodChannelFlutterSecureStorage(),
          DpapiJsonFileMapStorage(),
        );

  /// Internal constructor to initialize `FlutterSecureStorageWindows` with
  /// custom implementations for backward compatibility and platform-specific
  /// storage.
  ///
  /// Parameters:
  /// - [_backwardCompatible]: The storage mechanism used for backward
  ///   compatibility.
  /// - [_storage]: The platform-specific storage backend for Windows.
  FlutterSecureStorageWindows._(
    this._backwardCompatible,
    this._storage,
  );

  /// The storage implementation used for backward compatibility.
  final FlutterSecureStoragePlatform _backwardCompatible;

  /// The platform-specific storage implementation for Windows, using DPAPI.
  final MapStorage _storage;

  /// Serializes load/modify/save so concurrent writes cannot drop keys.
  Future<void> _opChain = Future<void>.value();

  /// Registers this plugin.
  static void registerWith() {
    FlutterSecureStoragePlatform.instance = FlutterSecureStorageWindows();
    DesktopPrivateKeyManager.instance = WindowsDesktopKeyManager();
  }

  Future<T> _serialized<T>(Future<T> Function() action) {
    final previous = _opChain;
    final gate = Completer<void>();
    _opChain = gate.future;
    return previous.then((_) => action()).whenComplete(gate.complete);
  }

  @override
  Future<bool> containsKey({
    required String key,
    required Map<String, String> options,
  }) {
    return _serialized(() async {
      final map = await _storage.load(options);
      if (map.containsKey(key)) {
        return true;
      }

      if (options.legacyMigrationEnabled) {
        return _backwardCompatible.containsKey(key: key, options: options);
      }

      return false;
    });
  }

  @override
  Future<void> delete({
    required String key,
    required Map<String, String> options,
  }) {
    return _serialized(() async {
      final map = await _storage.load(options);
      final initialSize = map.length;
      map.remove(key);
      if (map.length != initialSize) {
        await _storage.save(map, options);
      }

      if (options.legacyMigrationEnabled) {
        await _backwardCompatible.delete(key: key, options: options);
      }
    });
  }

  @override
  Future<void> deleteAll({required Map<String, String> options}) {
    return _serialized(() async {
      await _storage.clear(options);

      if (options.legacyMigrationEnabled) {
        await _backwardCompatible.deleteAll(options: options);
      }
    });
  }

  @override
  Future<String?> read({
    required String key,
    required Map<String, String> options,
  }) {
    return _serialized(() async {
      final map = await _storage.load(options);

      var result = map[key];
      if (options.legacyMigrationEnabled) {
        if (result == null) {
          final compatible =
              await _backwardCompatible.read(key: key, options: options);
          if (compatible != null) {
            // Write back now, so the value should be retrieved from JSON file
            // next.
            result = map[key] = compatible;
            await _storage.save(map, options);
          }
        }

        // Clear old entry.
        await _backwardCompatible.delete(key: key, options: options);
      }

      return result;
    });
  }

  @override
  Future<Map<String, String>> readAll({
    required Map<String, String> options,
  }) {
    return _serialized(() async {
      final map = await _storage.load(options);
      if (!options.legacyMigrationEnabled) {
        // Just return a map.
        return map;
      }

      final compatible = await _backwardCompatible.readAll(options: options);

      if (compatible.isEmpty) {
        return map;
      }

      for (final entry in compatible.entries) {
        map.putIfAbsent(entry.key, () => entry.value);
      }

      // Write back now, so the value should be retrieved from JSON file next.
      await _storage.save(map, options);

      // Clear old entries.
      await _backwardCompatible.deleteAll(options: options);

      return map;
    });
  }

  @override
  Future<void> write({
    required String key,
    required String value,
    required Map<String, String> options,
  }) {
    return _serialized(() async {
      final map = await _storage.load(options);
      map[key] = value;
      await _storage.save(map, options);

      if (options.legacyMigrationEnabled) {
        // Clear old entry.
        await _backwardCompatible.delete(key: key, options: options);
      }
    });
  }
}

/// Creates a custom instance of `FlutterSecureStorageWindows` for testing.
///
/// This factory function is annotated with `@visibleForTesting` to indicate
/// its intended use in testing scenarios. It allows specifying custom
/// implementations for backward compatibility and platform-specific storage.
///
/// Parameters:
/// - [backwardCompatible]: A custom implementation of
///   `FlutterSecureStoragePlatform` for backward-compatible storage behavior.
/// - [mapStorage]: A custom implementation of `MapStorage` for Windows secure
///   storage functionality.
///
/// Returns:
/// - An instance of `FlutterSecureStorageWindows` configured with the given
///   `backwardCompatible` and `mapStorage` implementations.
@visibleForTesting
FlutterSecureStorageWindows createFlutterSecureStorageWindows(
  FlutterSecureStoragePlatform backwardCompatible,
  MapStorage mapStorage,
) =>
    FlutterSecureStorageWindows._(backwardCompatible, mapStorage);

@visibleForTesting

/// An abstract class that defines the interface for map-based storage
/// implementations.
abstract class MapStorage {
  /// Loads a map of key-value pairs from the storage medium.
  ///
  /// Parameters:
  /// - [options]: A map of options to customize the load operation.
  FutureOr<Map<String, String>> load(Map<String, String> options);

  /// Saves a map of key-value pairs to the storage medium.
  ///
  /// Parameters:
  /// - [data]: A map containing the data to save.
  /// - [options]: A map of options to customize the save operation.
  FutureOr<void> save(Map<String, String> data, Map<String, String> options);

  /// Clears all key-value pairs from the storage medium.
  ///
  /// Parameters:
  /// - [options]: A map of options to customize the clear operation.
  FutureOr<void> clear(Map<String, String> options);
}

/// Default file name used to store encrypted JSON data (default namespace).
///
/// Exposed for testing; prefer [encryptedJsonFileNameForOptions].
@visibleForTesting
const String encryptedJsonFileName = 'flutter_secure_storage.dat';

/// One-time copy of [encryptedJsonFileName] taken before this version first
/// touched storage, when that file still held every namespace.
@visibleForTesting
const String legacySharedSnapshotFileName =
    'flutter_secure_storage.legacy-shared.dat';

/// Written once storage has been checked for a legacy shared file, so the
/// snapshot is never re-taken from the default namespace's newer contents.
@visibleForTesting
const String namespaceLayoutMarkerFileName =
    'flutter_secure_storage.namespaces-v2';

/// Suffix of the per-namespace marker recording that the namespace was seeded
/// from [legacySharedSnapshotFileName]; `deleteAll` keeps it so cleared data
/// is not seeded again.
@visibleForTesting
const String namespaceSeededSuffix = '.seeded';

/// Builds the DPAPI JSON filename for the [OptionsExtension.accountName]
/// in [options].
///
/// The default namespace keeps the legacy [encryptedJsonFileName] so existing
/// installs continue to read their data after upgrading. Custom namespaces get
/// a per-account file.
@visibleForTesting
String encryptedJsonFileNameForOptions(Map<String, String> options) {
  if (options.accountName == defaultWindowsAccountName) {
    return encryptedJsonFileName;
  }
  final safe = options.accountName.replaceAll(RegExp(r'[^\w\-.]'), '_');
  return 'flutter_secure_storage_$safe.dat';
}

/// A `MapStorage` implementation that uses DPAPI (Data Protection API) for
/// encryption and stores data in a JSON file on disk.
///
/// This implementation is specific to Windows platforms.
///
/// Writes are atomic (temp + rename) and keep a `.bak` of the previous good
/// file. On load failure the backup is tried before quarantining the corrupt
/// primary — the storage file is never deleted solely because it failed to
/// decrypt.
///
/// Releases before per-namespace files wrote every namespace into
/// [encryptedJsonFileName]. The first time this version runs it snapshots that
/// file; each custom namespace without a file of its own is seeded once from
/// the snapshot, so upgrading never hides existing secrets.
@visibleForTesting
class DpapiJsonFileMapStorage extends MapStorage {
  /// Creates an instance of `DpapiJsonFileMapStorage`.
  DpapiJsonFileMapStorage();

  bool _layoutChecked = false;

  /// Retrieves the canonical path to the encrypted JSON file used for storage.
  ///
  /// This method constructs the file path based on the application's support
  /// directory.
  ///
  /// Returns:
  /// - A [FutureOr] resolving to the canonical file path as a string.
  FutureOr<String> _getJsonFilePath(Map<String, String> options) async {
    final appDataDirectory = await getApplicationSupportDirectory();

    return path.canonicalize(
      path.join(
        appDataDirectory.path,
        encryptedJsonFileNameForOptions(options),
      ),
    );
  }

  /// Snapshots the legacy shared file once, before anything rewrites it.
  Future<void> _ensureLegacySnapshot() async {
    if (_layoutChecked) {
      return;
    }
    final directory = (await getApplicationSupportDirectory()).path;
    final marker = File(path.join(directory, namespaceLayoutMarkerFileName));
    if (!marker.existsSync()) {
      final shared = File(path.join(directory, encryptedJsonFileName));
      final snapshot =
          File(path.join(directory, legacySharedSnapshotFileName));
      try {
        if (shared.existsSync() && !snapshot.existsSync()) {
          final tmp = File('${snapshot.path}.tmp');
          await shared.copy(tmp.path);
          if (!snapshot.existsSync()) {
            await tmp.rename(snapshot.path);
          } else {
            await tmp.delete();
          }
        }
        await marker.create(recursive: true, exclusive: true);
      } on FileSystemException catch (e) {
        // Another isolate or process may have taken the snapshot first.
        debugPrint('Legacy secure storage snapshot step skipped: $e');
      }
    }
    _layoutChecked = true;
  }

  @override
  FutureOr<Map<String, String>> load(Map<String, String> options) async {
    await _ensureLegacySnapshot();
    final filePath = await _getJsonFilePath(options);
    final file = File(filePath);
    final backup = File('$filePath.bak');

    final primary = await _tryDecodeFile(file, options.dpapiFlags);
    if (primary != null) {
      return primary;
    }

    final fromBackup = await _tryDecodeFile(backup, options.dpapiFlags);
    if (fromBackup != null) {
      debugPrint(
        'Recovered flutter_secure_storage from backup: ${backup.path}',
      );
      try {
        if (file.existsSync()) {
          await _quarantineCorruptFile(file);
        }
        await backup.copy(file.path);
      } on FileSystemException catch (e) {
        debugPrint('Failed to restore secure storage backup: $e');
      }
      return fromBackup;
    }

    if (file.existsSync()) {
      await _quarantineCorruptFile(file);
      return {};
    }

    return _seedFromLegacySnapshot(filePath, options);
  }

  /// Seeds a custom namespace that has never had a file from the legacy
  /// shared snapshot. Runs at most once per namespace.
  Future<Map<String, String>> _seedFromLegacySnapshot(
    String filePath,
    Map<String, String> options,
  ) async {
    if (options.accountName == defaultWindowsAccountName) {
      return {};
    }
    final directory = path.dirname(filePath);
    final snapshot = File(path.join(directory, legacySharedSnapshotFileName));
    final seededMarker = File('$filePath$namespaceSeededSuffix');
    if (!snapshot.existsSync() || seededMarker.existsSync()) {
      return {};
    }

    // The shared file was always written with user-scope DPAPI.
    final seed = await _tryDecodeFile(snapshot, 0);
    if (seed != null && seed.isNotEmpty) {
      await save(seed, options);
      debugPrint(
        'Seeded secure storage namespace "${options.accountName}" from the '
        'legacy shared file (${seed.length} entries).',
      );
    }
    try {
      await seededMarker.create(recursive: true);
    } on FileSystemException catch (e) {
      debugPrint('Failed to mark secure storage namespace as seeded: $e');
    }
    return seed ?? {};
  }

  /// Decrypts and parses [file], or returns null when it is missing/unreadable.
  Future<Map<String, String>?> _tryDecodeFile(File file, int dpapiFlags) async {
    if (!file.existsSync()) {
      return null;
    }

    late final Uint8List encryptedText;
    try {
      encryptedText = await file.readAsBytes();
    } on FileSystemException catch (e) {
      debugPrint('Reading secure storage file failed (treated as missing): $e');
      return null;
    }

    if (encryptedText.isEmpty) {
      return null;
    }

    late final String plainText;
    try {
      plainText = using((alloc) {
        final pEncryptedText = alloc<Uint8>(encryptedText.length);
        pEncryptedText
            .asTypedList(encryptedText.length)
            .setAll(0, encryptedText);

        // Specify size of the struct explicitly.
        final encryptedTextBlob = alloc.allocate<CRYPT_INTEGER_BLOB>(
          sizeOf<CRYPT_INTEGER_BLOB>(),
        );
        encryptedTextBlob.ref.cbData = encryptedText.length;
        encryptedTextBlob.ref.pbData = pEncryptedText;

        // Specify size of the struct explicitly.
        final plainTextBlob = alloc.allocate<CRYPT_INTEGER_BLOB>(
          sizeOf<CRYPT_INTEGER_BLOB>(),
        );
        final Win32Result(
          value: decryptOk,
          error: decryptError,
        ) = CryptUnprotectData(
          encryptedTextBlob,
          null,
          null,
          null,
          dpapiFlags,
          plainTextBlob,
        );
        if (!decryptOk) {
          throw WindowsException(
            decryptError.toHRESULT(),
            message: 'Failure on CryptUnprotectData()',
          );
        }

        if (plainTextBlob.ref.pbData.address == NULL) {
          throw WindowsException(
            ERROR_OUTOFMEMORY.toHRESULT(),
            message: 'Failure on CryptUnprotectData()',
          );
        }

        try {
          return utf8.decoder.convert(
            plainTextBlob.ref.pbData.asTypedList(plainTextBlob.ref.cbData),
          );
        } finally {
          if (plainTextBlob.ref.pbData.address != NULL) {
            final Win32Result(value: freed, error: freeError) = LocalFree(
              HLOCAL(plainTextBlob.ref.pbData),
            );
            if (freed.address != NULL) {
              debugPrint(
                'load: Failed to LocalFree with: '
                '0x${freeError.toHRESULT().toHexString(32)}',
              );
            }
          }
        }
      });
    } on FormatException catch (e) {
      debugPrint('Failed to decrypt secure storage ${file.path}: $e');
      return null;
    } on WindowsException catch (e) {
      debugPrint('Failed to decrypt secure storage ${file.path}: $e');
      return null;
    }

    final Object? decoded;
    try {
      decoded = jsonDecode(plainText);
    } on FormatException catch (e) {
      debugPrint('Failed to parse secure storage JSON ${file.path}: $e');
      return null;
    }

    if (decoded is! Map) {
      debugPrint(
        'Failed to parse secure storage JSON ${file.path}: not an object',
      );
      return null;
    }

    return {
      for (final e in decoded.entries.where(
        (x) => x.key is String && x.value is String,
      ))
        e.key as String: e.value as String,
    };
  }

  /// Moves an unreadable primary aside instead of deleting key material.
  Future<void> _quarantineCorruptFile(File file) async {
    final quarantine = File(
      '${file.path}.corrupt.${DateTime.now().millisecondsSinceEpoch}',
    );
    try {
      await file.rename(quarantine.path);
      debugPrint(
        'Quarantined unreadable secure storage file: ${quarantine.path}',
      );
    } on FileSystemException catch (e) {
      debugPrint('Failed to quarantine secure storage file ${file.path}: $e');
    }
  }

  @override
  FutureOr<void> save(
    Map<String, String> data,
    Map<String, String> options,
  ) async {
    await _ensureLegacySnapshot();
    final file = File(await _getJsonFilePath(options));
    final json = jsonEncode(data);
    final plainText = utf8.encode(json);

    await using<FutureOr<void>>((alloc) async {
      final pPlainText = alloc<Uint8>(plainText.length);
      pPlainText.asTypedList(plainText.length).setAll(0, plainText);

      // Specify size of the struct explicitly.
      final plainTextBlob = alloc.allocate<CRYPT_INTEGER_BLOB>(
        sizeOf<CRYPT_INTEGER_BLOB>(),
      );
      plainTextBlob.ref.cbData = plainText.length;
      plainTextBlob.ref.pbData = pPlainText;

      // Specify size of the struct explicitly.
      final encryptedTextBlob = alloc.allocate<CRYPT_INTEGER_BLOB>(
        sizeOf<CRYPT_INTEGER_BLOB>(),
      );
      final Win32Result(
        value: encryptOk,
        error: encryptError,
      ) = CryptProtectData(
        plainTextBlob,
        null,
        null,
        null,
        options.dpapiFlags,
        encryptedTextBlob,
      );
      if (!encryptOk) {
        throw WindowsException(
          encryptError.toHRESULT(),
          message: 'Failure on CryptProtectData()',
        );
      }

      if (encryptedTextBlob.ref.pbData.address == NULL) {
        throw WindowsException(
          ERROR_OUTOFMEMORY.toHRESULT(),
          message: 'Failure on CryptProtectData()',
        );
      }

      try {
        final encryptedText = List<int>.from(
          encryptedTextBlob.ref.pbData.asTypedList(
            encryptedTextBlob.ref.cbData,
          ),
        );
        await _atomicWriteEncryptedBytes(file, encryptedText);
      } finally {
        if (encryptedTextBlob.ref.pbData.address != NULL) {
          final Win32Result(value: freed, error: freeError) = LocalFree(
            HLOCAL(encryptedTextBlob.ref.pbData),
          );
          if (freed.address != NULL) {
            debugPrint(
              'save: Failed to LocalFree with: '
              '0x${freeError.toHRESULT().toHexString(32)}',
            );
          }
        }
      }
    });
  }

  /// Writes [encryptedText] via temp file + rename, keeping a `.bak` previous.
  Future<void> _atomicWriteEncryptedBytes(
    File file,
    List<int> encryptedText,
  ) async {
    final tmp = File('${file.path}.tmp');
    final bak = File('${file.path}.bak');

    await file.parent.create(recursive: true);
    await tmp.writeAsBytes(encryptedText, flush: true);

    if (file.existsSync()) {
      if (bak.existsSync()) {
        await bak.delete();
      }
      await file.rename(bak.path);
    }

    // On Windows, rename fails if the destination already exists.
    if (file.existsSync()) {
      await file.delete();
    }
    await tmp.rename(file.path);
  }

  @override
  FutureOr<void> clear(Map<String, String> options) async {
    await _ensureLegacySnapshot();
    final filePath = await _getJsonFilePath(options);
    // The `.seeded` marker stays so cleared data is not seeded again.
    await _deleteIfExists(File(filePath));
    await _deleteIfExists(File('$filePath.bak'));
    await _deleteIfExists(File('$filePath.tmp'));
  }

  Future<void> _deleteIfExists(File file) async {
    if (!file.existsSync()) {
      return;
    }
    try {
      await file.delete();
    } on FileSystemException catch (e) {
      debugPrint('Deleting secure storage file already gone: ${file.path} $e');
    }
  }
}
