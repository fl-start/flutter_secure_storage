import 'dart:typed_data';

import 'desktop_enums.dart';
import 'desktop_errors.dart';
import 'desktop_key_id.dart';

/// Creation options for a desktop private key.
class DesktopPrivateKeyOptions {
  /// Creates private-key options.
  ///
  /// [machineScoped] defaults to `false` (user-scoped).
  /// [exportPolicy] defaults to [PrivateKeyExportPolicy.nonExportable].
  DesktopPrivateKeyOptions({
    required this.keyId,
    required this.algorithm,
    this.protection = DesktopSecureStorageProtection.platformDefault,
    this.exportPolicy = PrivateKeyExportPolicy.nonExportable,
    this.requireUserPresence = false,
    this.machineScoped = false,
    this.accountName,
    this.metadata = const <String, String>{},
  }) {
    normalizeAndValidateKeyId(keyId);
    _rejectContradictions();
  }

  /// Application-namespaced key identifier.
  final String keyId;

  /// Asymmetric algorithm. Never silently substituted.
  final DesktopKeyAlgorithm algorithm;

  /// Hardware / software protection policy.
  final DesktopSecureStorageProtection protection;

  /// Immutable export policy.
  final PrivateKeyExportPolicy exportPolicy;

  /// Require user presence (biometric / passcode) when supported.
  final bool requireUserPresence;

  /// Machine-wide scope. Defaults to `false` (user-scoped).
  final bool machineScoped;

  /// Optional account / namespace for isolation.
  final String? accountName;

  /// Non-secret metadata. Must never contain private-key material.
  final Map<String, String> metadata;

  void _rejectContradictions() {
    for (final entry in metadata.entries) {
      final lowered = '${entry.key}:${entry.value}'.toLowerCase();
      if (lowered.contains('private') && lowered.contains('key')) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.invalidConfiguration,
          message: 'metadata must not contain private-key material',
        );
      }
    }
    if (exportPolicy == PrivateKeyExportPolicy.exportableEncrypted &&
        protection == DesktopSecureStorageProtection.hardwareBackedRequired &&
        algorithm == DesktopKeyAlgorithm.ed25519) {
      // Ed25519 is never hardware-resident on common desktop TPMs/SE;
      // requiring hardware for the private key itself is invalid.
      // Callers who want hardware wrapping should use hardwareBackedPreferred
      // or accept storageProtectionHardwareBacked via provider selection.
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.invalidConfiguration,
        message:
            'ed25519 cannot satisfy hardwareBackedRequired for a private key '
            'that must remain exportable; use hardwareBackedPreferred or '
            'softwareProtected',
      );
    }
  }

  /// Serializes for method channels.
  Map<String, Object?> toMap() => <String, Object?>{
        'keyId': keyId,
        'algorithm': algorithm.name,
        'protection': protection.name,
        'exportPolicy': exportPolicy.name,
        'requireUserPresence': requireUserPresence,
        'machineScoped': machineScoped,
        'accountName': accountName,
        'metadata': metadata,
      };
}

/// Opaque handle describing a persisted private key (never contains key bytes).
class DesktopPrivateKeyHandle {
  /// Creates a handle.
  const DesktopPrivateKeyHandle({
    required this.keyId,
    required this.provider,
    required this.algorithm,
    required this.exportPolicy,
    required this.hardwareBacked,
    required this.deviceBound,
    required this.machineScoped,
    required this.userPresenceRequired,
    this.storageProtectionHardwareBacked = false,
  });

  final String keyId;
  final String provider;
  final DesktopKeyAlgorithm algorithm;
  final PrivateKeyExportPolicy exportPolicy;

  /// True only when the private key itself resides in hardware/token.
  final bool hardwareBacked;

  /// True when storage wrapping uses hardware (may differ from [hardwareBacked]).
  final bool storageProtectionHardwareBacked;

  final bool deviceBound;
  final bool machineScoped;
  final bool userPresenceRequired;

  factory DesktopPrivateKeyHandle.fromMap(Map<Object?, Object?> map) {
    DesktopKeyAlgorithm parseAlgorithm(String? name) =>
        DesktopKeyAlgorithm.values.firstWhere(
          (e) => e.name == name,
          orElse: () => DesktopKeyAlgorithm.ecP256,
        );

    PrivateKeyExportPolicy parseExport(String? name) =>
        PrivateKeyExportPolicy.values.firstWhere(
          (e) => e.name == name,
          orElse: () => PrivateKeyExportPolicy.nonExportable,
        );

    return DesktopPrivateKeyHandle(
      keyId: map['keyId']?.toString() ?? '',
      provider: map['provider']?.toString() ?? '',
      algorithm: parseAlgorithm(map['algorithm']?.toString()),
      exportPolicy: parseExport(map['exportPolicy']?.toString()),
      hardwareBacked: map['hardwareBacked'] == true,
      storageProtectionHardwareBacked:
          map['storageProtectionHardwareBacked'] == true,
      deviceBound: map['deviceBound'] == true,
      machineScoped: map['machineScoped'] == true,
      userPresenceRequired: map['userPresenceRequired'] == true,
    );
  }

  Map<String, Object?> toMap() => <String, Object?>{
        'keyId': keyId,
        'provider': provider,
        'algorithm': algorithm.name,
        'exportPolicy': exportPolicy.name,
        'hardwareBacked': hardwareBacked,
        'storageProtectionHardwareBacked': storageProtectionHardwareBacked,
        'deviceBound': deviceBound,
        'machineScoped': machineScoped,
        'userPresenceRequired': userPresenceRequired,
      };
}

/// Argon2id parameters for encrypted export (optional).
class Argon2idParameters {
  const Argon2idParameters({
    this.memoryKb = 65536,
    this.iterations = 3,
    this.parallelism = 1,
  });

  final int memoryKb;
  final int iterations;
  final int parallelism;

  Map<String, Object?> toMap() => <String, Object?>{
        'memoryKb': memoryKb,
        'iterations': iterations,
        'parallelism': parallelism,
      };
}

/// Options for encrypted PKCS#8 export.
///
/// Prefer [passphraseBytes] over [passphrase]. Dart [String] values cannot be
/// reliably wiped from memory after use.
class PrivateKeyExportOptions {
  PrivateKeyExportOptions({
    required this.encoding,
    this.passphrase,
    this.passphraseBytes,
    this.kdf = PrivateKeyKdf.pbkdf2Sha256,
    this.pbkdf2Iterations = 310000,
    this.argon2id,
  }) {
    final hasString = passphrase != null && passphrase!.isNotEmpty;
    final hasBytes = passphraseBytes != null && passphraseBytes!.isNotEmpty;
    if (!hasString && !hasBytes) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.invalidExportPassphrase,
        message: 'export passphrase must be non-empty',
      );
    }
  }

  final PrivateKeyEncoding encoding;
  final String? passphrase;
  final Uint8List? passphraseBytes;
  final PrivateKeyKdf kdf;
  final int? pbkdf2Iterations;
  final Argon2idParameters? argon2id;

  Map<String, Object?> toMap() => <String, Object?>{
        'encoding': encoding.name,
        'passphrase': passphrase,
        'passphraseBytes': passphraseBytes,
        'kdf': kdf.name,
        'pbkdf2Iterations': pbkdf2Iterations,
        'argon2id': argon2id?.toMap(),
      };
}

/// Encrypted private-key export blob (never plaintext).
class ExportedPrivateKey {
  const ExportedPrivateKey({
    required this.bytes,
    required this.encoding,
    required this.kdf,
  });

  final Uint8List bytes;
  final PrivateKeyEncoding encoding;
  final PrivateKeyKdf kdf;

  factory ExportedPrivateKey.fromMap(Map<Object?, Object?> map) {
    final raw = map['bytes'];
    final bytes = raw is Uint8List
        ? raw
        : Uint8List.fromList(List<int>.from(raw as List<dynamic>? ?? const []));
    return ExportedPrivateKey(
      bytes: bytes,
      encoding: PrivateKeyEncoding.values.firstWhere(
        (e) => e.name == map['encoding']?.toString(),
        orElse: () => PrivateKeyEncoding.pemPkcs8,
      ),
      kdf: PrivateKeyKdf.values.firstWhere(
        (e) => e.name == map['kdf']?.toString(),
        orElse: () => PrivateKeyKdf.pbkdf2Sha256,
      ),
    );
  }
}

/// Options for importing an encrypted PKCS#8 private key.
class PrivateKeyImportOptions {
  PrivateKeyImportOptions({
    required this.keyId,
    required this.protection,
    required this.exportPolicy,
    this.passphrase,
    this.passphraseBytes,
    this.machineScoped = false,
    this.accountName,
    this.requireUserPresence = false,
  }) {
    normalizeAndValidateKeyId(keyId);
  }

  final String keyId;
  final DesktopSecureStorageProtection protection;
  final PrivateKeyExportPolicy exportPolicy;
  final String? passphrase;
  final Uint8List? passphraseBytes;
  final bool machineScoped;
  final String? accountName;
  final bool requireUserPresence;

  Map<String, Object?> toMap() => <String, Object?>{
        'keyId': keyId,
        'protection': protection.name,
        'exportPolicy': exportPolicy.name,
        'passphrase': passphrase,
        'passphraseBytes': passphraseBytes,
        'machineScoped': machineScoped,
        'accountName': accountName,
        'requireUserPresence': requireUserPresence,
      };
}

/// Result of importing a private key.
class ImportedPrivateKey {
  const ImportedPrivateKey({required this.handle});

  final DesktopPrivateKeyHandle handle;

  factory ImportedPrivateKey.fromMap(Map<Object?, Object?> map) {
    final handleMap = Map<Object?, Object?>.from(
      map['handle'] as Map? ?? const <Object?, Object?>{},
    );
    return ImportedPrivateKey(
      handle: DesktopPrivateKeyHandle.fromMap(handleMap),
    );
  }
}

/// CSR subject / extension options.
class CertificateSigningRequestOptions {
  const CertificateSigningRequestOptions({
    required this.subjectDistinguishedName,
    this.dnsNames = const <String>[],
  });

  /// e.g. `CN=device.example,O=Example`
  final String subjectDistinguishedName;
  final List<String> dnsNames;

  Map<String, Object?> toMap() => <String, Object?>{
        'subjectDistinguishedName': subjectDistinguishedName,
        'dnsNames': dnsNames,
      };
}
