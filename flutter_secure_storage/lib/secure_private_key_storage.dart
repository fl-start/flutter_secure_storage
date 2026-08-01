/// Unified private-key APIs for mobile and desktop.
///
/// Supported: Android, iOS, Windows, macOS, Linux.
/// **Web is not supported** by this fork and always throws
/// [DesktopSecureStorageErrorCode.unsupportedPlatform].
library;

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';

export 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';

/// High-level private-key manager for supported native platforms.
///
/// Prefer [SecurePrivateKeyStorage.privateKeys].
///
/// [DesktopSecureStorage] is a compatibility typedef for this class.
class SecurePrivateKeyStorage {
  /// Creates a private-key facade.
  const SecurePrivateKeyStorage({DesktopPrivateKeyManager? keyManager})
      : _keys = keyManager;

  final DesktopPrivateKeyManager? _keys;

  DesktopPrivateKeyManager get _manager =>
      _keys ?? DesktopPrivateKeyManager.instance;

  /// Shared private-key API entry point.
  static const SecurePrivateKeyStorage privateKeys = SecurePrivateKeyStorage();

  /// Whether the current platform supports the private-key API.
  ///
  /// Always `false` on Web.
  static bool get isSupported {
    if (kIsWeb) {
      return false;
    }
    switch (defaultTargetPlatform) {
      case TargetPlatform.android:
      case TargetPlatform.iOS:
      case TargetPlatform.windows:
      case TargetPlatform.macOS:
      case TargetPlatform.linux:
        return true;
      case TargetPlatform.fuchsia:
        return false;
    }
  }

  /// Whether the current platform is a desktop private-key target.
  ///
  /// Prefer [isSupported] for new code (includes mobile).
  static bool get isDesktopSupported {
    if (kIsWeb) {
      return false;
    }
    return defaultTargetPlatform == TargetPlatform.windows ||
        defaultTargetPlatform == TargetPlatform.macOS ||
        defaultTargetPlatform == TargetPlatform.linux;
  }

  void _ensureSupported() {
    if (!isSupported) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.unsupportedPlatform,
        message:
            'Private-key APIs are available on Android, iOS, Windows, macOS, '
            'and Linux. Web is not supported.',
      );
    }
  }

  /// Creates a private key under an immutable export / protection policy.
  Future<DesktopPrivateKeyHandle> createPrivateKey(
    DesktopPrivateKeyOptions options,
  ) {
    _ensureSupported();
    return _manager.createPrivateKey(options);
  }

  /// Returns a handle for [keyId], or `null` if missing.
  Future<DesktopPrivateKeyHandle?> getPrivateKeyHandle(String keyId) {
    _ensureSupported();
    return _manager.getPrivateKeyHandle(keyId);
  }

  /// Lists all persisted private-key handles.
  Future<List<DesktopPrivateKeyHandle>> listPrivateKeys() {
    _ensureSupported();
    return _manager.listPrivateKeys();
  }

  /// Returns the public key for [keyId].
  Future<Uint8List> getPublicKey(
    String keyId, {
    PublicKeyEncoding encoding = PublicKeyEncoding.spkiDer,
  }) {
    _ensureSupported();
    return _manager.getPublicKey(keyId, encoding: encoding);
  }

  /// Signs [data] with the private key identified by [keyId].
  Future<Uint8List> sign(
    String keyId,
    Uint8List data, {
    required SignatureAlgorithm algorithm,
  }) {
    _ensureSupported();
    return _manager.sign(keyId, data, algorithm: algorithm);
  }

  /// Returns encrypted PKCS#8 (or platform encrypted export). Never plaintext.
  Future<ExportedPrivateKey> exportPrivateKey(
    String keyId,
    PrivateKeyExportOptions options,
  ) {
    _ensureSupported();
    return _manager.exportPrivateKey(keyId, options);
  }

  /// Imports an encrypted private key under [options].
  Future<ImportedPrivateKey> importPrivateKey(
    Uint8List encryptedKey,
    PrivateKeyImportOptions options,
  ) {
    _ensureSupported();
    return _manager.importPrivateKey(encryptedKey, options);
  }

  /// Deletes the private key identified by [keyId].
  Future<void> deletePrivateKey(String keyId) {
    _ensureSupported();
    return _manager.deletePrivateKey(keyId);
  }

  /// Returns effective capabilities for the selected [protection] policy.
  Future<DesktopSecureStorageCapabilities> getCapabilities({
    DesktopSecureStorageProtection protection =
        DesktopSecureStorageProtection.platformDefault,
  }) {
    _ensureSupported();
    return _manager.getCapabilities(protection: protection);
  }

  /// Creates a certificate signing request for [keyId].
  Future<Uint8List> createCertificateSigningRequest(
    String keyId,
    CertificateSigningRequestOptions options,
  ) {
    _ensureSupported();
    return _manager.createCertificateSigningRequest(keyId, options);
  }
}

/// Compatibility alias for [SecurePrivateKeyStorage].
typedef DesktopSecureStorage = SecurePrivateKeyStorage;
