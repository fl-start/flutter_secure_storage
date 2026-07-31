/// Desktop hardware-backed secure storage and private-key APIs.
///
/// Mobile platforms (Android / iOS / Web) are unsupported for these APIs and
/// throw [DesktopSecureStorageException] with
/// [DesktopSecureStorageErrorCode.unsupportedPlatform].
library;

import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';

export 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';

/// High-level desktop private-key manager.
///
/// Prefer constructing via [DesktopSecureStorage.privateKeys].
class DesktopSecureStorage {
  /// Creates a desktop secure-storage facade.
  const DesktopSecureStorage({DesktopPrivateKeyManager? keyManager})
      : _keys = keyManager;

  final DesktopPrivateKeyManager? _keys;

  DesktopPrivateKeyManager get _manager =>
      _keys ?? DesktopPrivateKeyManager.instance;

  /// Shared private-key API entry point.
  static const DesktopSecureStorage privateKeys = DesktopSecureStorage();

  /// Whether the current Dart platform is a supported desktop target.
  static bool get isDesktopSupported {
    if (kIsWeb) {
      return false;
    }
    return defaultTargetPlatform == TargetPlatform.windows ||
        defaultTargetPlatform == TargetPlatform.macOS ||
        defaultTargetPlatform == TargetPlatform.linux;
  }

  void _ensureDesktop() {
    if (!isDesktopSupported) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.unsupportedPlatform,
        message:
            'Desktop private-key APIs are only available on Windows, macOS, and Linux',
      );
    }
  }

  /// Creates a private key under an immutable export / protection policy.
  Future<DesktopPrivateKeyHandle> createPrivateKey(
    DesktopPrivateKeyOptions options,
  ) {
    _ensureDesktop();
    return _manager.createPrivateKey(options);
  }

  Future<DesktopPrivateKeyHandle?> getPrivateKeyHandle(String keyId) {
    _ensureDesktop();
    return _manager.getPrivateKeyHandle(keyId);
  }

  Future<List<DesktopPrivateKeyHandle>> listPrivateKeys() {
    _ensureDesktop();
    return _manager.listPrivateKeys();
  }

  Future<Uint8List> getPublicKey(
    String keyId, {
    PublicKeyEncoding encoding = PublicKeyEncoding.spkiDer,
  }) {
    _ensureDesktop();
    return _manager.getPublicKey(keyId, encoding: encoding);
  }

  Future<Uint8List> sign(
    String keyId,
    Uint8List data, {
    required SignatureAlgorithm algorithm,
  }) {
    _ensureDesktop();
    return _manager.sign(keyId, data, algorithm: algorithm);
  }

  /// Returns encrypted PKCS#8 only. Never plaintext private-key bytes.
  Future<ExportedPrivateKey> exportPrivateKey(
    String keyId,
    PrivateKeyExportOptions options,
  ) {
    _ensureDesktop();
    return _manager.exportPrivateKey(keyId, options);
  }

  Future<ImportedPrivateKey> importPrivateKey(
    Uint8List encryptedKey,
    PrivateKeyImportOptions options,
  ) {
    _ensureDesktop();
    return _manager.importPrivateKey(encryptedKey, options);
  }

  Future<void> deletePrivateKey(String keyId) {
    _ensureDesktop();
    return _manager.deletePrivateKey(keyId);
  }

  Future<DesktopSecureStorageCapabilities> getCapabilities({
    DesktopSecureStorageProtection protection =
        DesktopSecureStorageProtection.platformDefault,
  }) {
    _ensureDesktop();
    return _manager.getCapabilities(protection: protection);
  }

  Future<Uint8List> createCertificateSigningRequest(
    String keyId,
    CertificateSigningRequestOptions options,
  ) {
    _ensureDesktop();
    return _manager.createCertificateSigningRequest(keyId, options);
  }
}
