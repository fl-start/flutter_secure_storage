import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:plugin_platform_interface/plugin_platform_interface.dart';

import 'desktop_capabilities.dart';
import 'desktop_enums.dart';
import 'desktop_errors.dart';
import 'desktop_private_key.dart';

/// Desktop private-key management API (Windows / macOS / Linux only).
abstract class DesktopPrivateKeyManager extends PlatformInterface {
  /// Creates a manager.
  DesktopPrivateKeyManager() : super(token: _token);

  static final Object _token = Object();

  static DesktopPrivateKeyManager _instance =
      MethodChannelDesktopPrivateKeyManager();

  /// Current instance.
  static DesktopPrivateKeyManager get instance => _instance;

  /// Overrides the instance (tests / platform registration).
  static set instance(DesktopPrivateKeyManager instance) {
    PlatformInterface.verifyToken(instance, _token);
    _instance = instance;
  }

  Future<DesktopPrivateKeyHandle> createPrivateKey(
    DesktopPrivateKeyOptions options,
  );

  Future<DesktopPrivateKeyHandle?> getPrivateKeyHandle(String keyId);

  Future<List<DesktopPrivateKeyHandle>> listPrivateKeys();

  Future<Uint8List> getPublicKey(
    String keyId, {
    PublicKeyEncoding encoding = PublicKeyEncoding.spkiDer,
  });

  Future<Uint8List> sign(
    String keyId,
    Uint8List data, {
    required SignatureAlgorithm algorithm,
  });

  Future<ExportedPrivateKey> exportPrivateKey(
    String keyId,
    PrivateKeyExportOptions options,
  );

  Future<ImportedPrivateKey> importPrivateKey(
    Uint8List encryptedKey,
    PrivateKeyImportOptions options,
  );

  Future<void> deletePrivateKey(String keyId);

  Future<DesktopSecureStorageCapabilities> getCapabilities({
    DesktopSecureStorageProtection protection =
        DesktopSecureStorageProtection.platformDefault,
  });

  Future<Uint8List> createCertificateSigningRequest(
    String keyId,
    CertificateSigningRequestOptions options,
  );
}

/// Default method-channel implementation.
class MethodChannelDesktopPrivateKeyManager extends DesktopPrivateKeyManager {
  MethodChannelDesktopPrivateKeyManager({
    MethodChannel? channel,
  }) : _channel = channel ??
            const MethodChannel(
              'plugins.it_nomads.com/flutter_secure_storage/desktop_keys',
            );

  final MethodChannel _channel;

  Future<T> _invoke<T>(String method, [Map<String, Object?>? args]) async {
    try {
      final result = await _channel.invokeMethod<T>(method, args);
      return result as T;
    } on PlatformException catch (e) {
      throw DesktopSecureStorageException(
        code: DesktopSecureStorageException.parseCode(e.code),
        message: e.message ?? e.code,
        details: e.details is Map
            ? Map<String, Object?>.from(e.details as Map)
            : <String, Object?>{'raw': e.details},
        provider: e.details is Map
            ? (e.details as Map)['provider']?.toString()
            : null,
        nativeStatusCode: e.details is Map
            ? int.tryParse('${(e.details as Map)['nativeStatusCode']}')
            : null,
      );
    } on MissingPluginException {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.unsupportedPlatform,
        message: 'desktop private-key API is unavailable on this platform',
      );
    }
  }

  @override
  Future<DesktopPrivateKeyHandle> createPrivateKey(
    DesktopPrivateKeyOptions options,
  ) async {
    final map = await _invoke<Map<Object?, Object?>>(
      'createPrivateKey',
      options.toMap(),
    );
    return DesktopPrivateKeyHandle.fromMap(map);
  }

  @override
  Future<DesktopPrivateKeyHandle?> getPrivateKeyHandle(String keyId) async {
    final map = await _invoke<Map<Object?, Object?>?>(
      'getPrivateKeyHandle',
      <String, Object?>{'keyId': keyId},
    );
    if (map == null) {
      return null;
    }
    return DesktopPrivateKeyHandle.fromMap(map);
  }

  @override
  Future<List<DesktopPrivateKeyHandle>> listPrivateKeys() async {
    final list = await _invoke<List<Object?>>('listPrivateKeys');
    return list
        .whereType<Map>()
        .map(
          (e) => DesktopPrivateKeyHandle.fromMap(
            Map<Object?, Object?>.from(e),
          ),
        )
        .toList(growable: false);
  }

  @override
  Future<Uint8List> getPublicKey(
    String keyId, {
    PublicKeyEncoding encoding = PublicKeyEncoding.spkiDer,
  }) async {
    final raw = await _invoke<dynamic>(
      'getPublicKey',
      <String, Object?>{
        'keyId': keyId,
        'encoding': encoding.name,
      },
    );
    return _asBytes(raw);
  }

  @override
  Future<Uint8List> sign(
    String keyId,
    Uint8List data, {
    required SignatureAlgorithm algorithm,
  }) async {
    final raw = await _invoke<dynamic>(
      'sign',
      <String, Object?>{
        'keyId': keyId,
        'data': data,
        'algorithm': algorithm.name,
      },
    );
    return _asBytes(raw);
  }

  @override
  Future<ExportedPrivateKey> exportPrivateKey(
    String keyId,
    PrivateKeyExportOptions options,
  ) async {
    final map = await _invoke<Map<Object?, Object?>>(
      'exportPrivateKey',
      <String, Object?>{
        'keyId': keyId,
        ...options.toMap(),
      },
    );
    return ExportedPrivateKey.fromMap(map);
  }

  @override
  Future<ImportedPrivateKey> importPrivateKey(
    Uint8List encryptedKey,
    PrivateKeyImportOptions options,
  ) async {
    final map = await _invoke<Map<Object?, Object?>>(
      'importPrivateKey',
      <String, Object?>{
        'encryptedKey': encryptedKey,
        ...options.toMap(),
      },
    );
    return ImportedPrivateKey.fromMap(map);
  }

  @override
  Future<void> deletePrivateKey(String keyId) async {
    await _invoke<void>(
      'deletePrivateKey',
      <String, Object?>{'keyId': keyId},
    );
  }

  @override
  Future<DesktopSecureStorageCapabilities> getCapabilities({
    DesktopSecureStorageProtection protection =
        DesktopSecureStorageProtection.platformDefault,
  }) async {
    final map = await _invoke<Map<Object?, Object?>>(
      'getCapabilities',
      <String, Object?>{'protection': protection.name},
    );
    return DesktopSecureStorageCapabilities.fromMap(map);
  }

  @override
  Future<Uint8List> createCertificateSigningRequest(
    String keyId,
    CertificateSigningRequestOptions options,
  ) async {
    final raw = await _invoke<dynamic>(
      'createCertificateSigningRequest',
      <String, Object?>{
        'keyId': keyId,
        ...options.toMap(),
      },
    );
    return _asBytes(raw);
  }

  Uint8List _asBytes(dynamic raw) {
    if (raw is Uint8List) {
      return raw;
    }
    if (raw is List) {
      return Uint8List.fromList(raw.cast<int>());
    }
    throw const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.unknown,
      message: 'expected bytes from platform channel',
    );
  }
}
