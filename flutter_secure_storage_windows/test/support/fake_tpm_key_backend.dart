import 'dart:typed_data';

import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:flutter_secure_storage_windows/src/desktop/windows_tpm_key_backend.dart';

/// In-memory [WindowsTpmKeyBackend] for tests: software keys from the
/// installed [DesktopCryptoBackend] stand in for TPM-resident keys.
final class FakeTpmKeyBackend implements WindowsTpmKeyBackend {
  FakeTpmKeyBackend({this.available = true});

  bool available;

  /// When set, [createKey] throws this.
  DesktopSecureStorageException? createError;

  /// When set, [deleteKey] throws this.
  DesktopSecureStorageException? deleteError;

  final Map<String, DesktopKeyPairDer> keys = {};
  final List<String> deleted = [];

  @override
  bool probe() => available;

  @override
  Uint8List createKey({
    required String keyName,
    required DesktopKeyAlgorithm algorithm,
    required bool machineScoped,
  }) {
    final error = createError;
    if (error != null) {
      throw error;
    }
    final pair = DesktopCryptoBackend.current.generateKeyPair(algorithm);
    keys[keyName] = pair;
    return pair.spkiDer;
  }

  @override
  Uint8List publicKeySpki({
    required String keyName,
    required DesktopKeyAlgorithm algorithm,
    required bool machineScoped,
  }) =>
      _key(keyName).spkiDer;

  @override
  Uint8List sign({
    required String keyName,
    required DesktopKeyAlgorithm algorithm,
    required bool machineScoped,
    required Uint8List data,
    required SignatureAlgorithm signatureAlgorithm,
  }) =>
      DesktopCryptoBackend.current.sign(
        _key(keyName).pkcs8Der,
        data,
        algorithm: algorithm,
      );

  @override
  void deleteKey({required String keyName, required bool machineScoped}) {
    final error = deleteError;
    if (error != null) {
      throw error;
    }
    keys.remove(keyName);
    deleted.add(keyName);
  }

  DesktopKeyPairDer _key(String keyName) =>
      keys[keyName] ??
      (throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyNotFound,
        message: 'no such TPM key',
      ));
}
