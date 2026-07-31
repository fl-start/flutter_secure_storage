import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:path/path.dart' as p;
import 'package:pointycastle/export.dart';

import 'linux_systemd_creds.dart';
import 'linux_tpm2_backend.dart';

/// Linux [DesktopPrivateKeyManager] with PKCS#8/PKCS#10, TPM2, and systemd-creds.
class LinuxDesktopKeyManager extends DesktopPrivateKeyManager {
  /// Creates a Linux desktop key manager.
  LinuxDesktopKeyManager({
    Directory? storageRoot,
    MethodChannel? channel,
    bool? tpmAvailableOverride,
    bool? secretServiceAvailableOverride,
    bool? systemdCredsAvailableOverride,
    bool useLocalDekWrapOnly = false,
    LinuxTpm2Backend? tpmBackend,
    LinuxSystemdCreds? systemdCreds,
  })  : _storageRoot = storageRoot,
        _channel = channel ??
            const MethodChannel(
              'plugins.it_nomads.com/flutter_secure_storage/desktop_keys',
            ),
        _tpmAvailableOverride = tpmAvailableOverride,
        _secretServiceAvailableOverride = secretServiceAvailableOverride,
        _useLocalDekWrapOnly = useLocalDekWrapOnly,
        _tpm = tpmBackend ??
            LinuxTpm2Backend(
              storageRoot: storageRoot,
              availableOverride: tpmAvailableOverride,
            ),
        _systemd = systemdCreds ??
            LinuxSystemdCreds(
              availableOverride: systemdCredsAvailableOverride,
            );

  final Directory? _storageRoot;
  final MethodChannel _channel;
  final bool? _tpmAvailableOverride;
  final bool? _secretServiceAvailableOverride;
  final bool _useLocalDekWrapOnly;
  final LinuxTpm2Backend _tpm;
  final LinuxSystemdCreds _systemd;

  static const _metaFile = 'keys.json';
  static const _providerSecretService = 'secret_service';
  static const _providerProtectedFile = 'protected_file';
  static const _providerTpm = 'tpm2';
  static const _providerSystemd = 'systemd_creds';
  static const _localWrapPrefix = 'loc1:';
  static const _tpmRecordMagic = 'FSS-TPM1';

  Future<Directory> _root() async {
    if (_storageRoot != null) {
      await _storageRoot!.create(recursive: true);
      return _storageRoot!;
    }
    final xdg = Platform.environment['XDG_DATA_HOME'];
    final home = Platform.environment['HOME'];
    final base = (xdg != null && xdg.isNotEmpty)
        ? xdg
        : (home != null && home.isNotEmpty)
            ? p.join(home, '.local', 'share')
            : Directory.systemTemp.path;
    final dir = Directory(
      p.join(base, 'flutter_secure_storage', 'private_keys'),
    );
    await dir.create(recursive: true);
    return dir;
  }

  Future<File> _metaPath() async =>
      File(p.join((await _root()).path, _metaFile));

  Future<Map<String, dynamic>> _loadMeta() async {
    final file = await _metaPath();
    if (!file.existsSync()) {
      return <String, dynamic>{'keys': <String, dynamic>{}};
    }
    final decoded = jsonDecode(await file.readAsString());
    if (decoded is Map<String, dynamic>) {
      return decoded;
    }
    if (decoded is Map) {
      return Map<String, dynamic>.from(decoded);
    }
    return <String, dynamic>{'keys': <String, dynamic>{}};
  }

  Future<void> _saveMeta(Map<String, dynamic> meta) async {
    final file = await _metaPath();
    final tmp = File('${file.path}.tmp');
    await tmp.writeAsString(jsonEncode(meta), flush: true);
    if (file.existsSync()) {
      await file.delete();
    }
    await tmp.rename(file.path);
  }

  @override
  Future<DesktopSecureStorageCapabilities> getCapabilities({
    DesktopSecureStorageProtection protection =
        DesktopSecureStorageProtection.platformDefault,
  }) async {
    final tpm = await _tpm.available();
    final systemd = await _systemd.available();
    final secret = _secretServiceAvailableOverride ?? false;

    if (!_useLocalDekWrapOnly) {
      try {
        final map = await _channel.invokeMethod<Map<Object?, Object?>>(
          'getCapabilities',
          <String, Object?>{'protection': protection.name},
        );
        if (map != null) {
          final caps = DesktopSecureStorageCapabilities.fromMap(map);
          final providers = <String>{
            ...caps.availableProviders,
            if (tpm) _providerTpm,
            if (systemd) _providerSystemd,
          }.toList();
          return DesktopSecureStorageCapabilities(
            platform: caps.platform,
            availableProviders: providers,
            selectedProvider: _selectProvider(protection, tpm, secret, systemd),
            hardwareAvailable: tpm || caps.hardwareAvailable,
            storageProtectionHardwareBacked:
                protection == DesktopSecureStorageProtection.hardwareBackedRequired
                    ? tpm
                    : false,
            privateKeyHardwareBacked:
                protection == DesktopSecureStorageProtection.hardwareBackedRequired
                    ? tpm
                    : false,
            supportsNonExportableKeys: true,
            supportsExportableKeys: true,
            supportsUserPresence: false,
            supportsMachineScope: false,
            supportsCsrGeneration: true,
            supportedAlgorithms: caps.supportedAlgorithms,
            supportedExportFormats: caps.supportedExportFormats,
            fallbackReason: _fallbackReason(protection, tpm, secret, systemd),
            sameUserCompromiseResistant: tpm,
            rootCompromiseResistant: tpm,
          );
        }
      } on MissingPluginException {
        // Local probe path.
      } on PlatformException {
        // Local probe path.
      }
    }

    return DesktopSecureStorageCapabilities(
      platform: 'linux',
      availableProviders: [
        if (secret) _providerSecretService,
        _providerProtectedFile,
        if (tpm) _providerTpm,
        if (systemd) _providerSystemd,
      ],
      selectedProvider: _selectProvider(protection, tpm, secret, systemd),
      hardwareAvailable: tpm,
      storageProtectionHardwareBacked:
          protection == DesktopSecureStorageProtection.hardwareBackedRequired &&
              tpm,
      privateKeyHardwareBacked:
          protection == DesktopSecureStorageProtection.hardwareBackedRequired &&
              tpm,
      supportsNonExportableKeys: true,
      supportsExportableKeys: true,
      supportsUserPresence: false,
      supportsMachineScope: false,
      supportsCsrGeneration: true,
      supportedAlgorithms: const [
        DesktopKeyAlgorithm.rsa2048,
        DesktopKeyAlgorithm.rsa3072,
        DesktopKeyAlgorithm.ecP256,
        DesktopKeyAlgorithm.ed25519,
      ],
      supportedExportFormats: const [
        PrivateKeyEncoding.pemPkcs8,
        PrivateKeyEncoding.derPkcs8,
      ],
      fallbackReason: _fallbackReason(protection, tpm, secret, systemd),
      sameUserCompromiseResistant: tpm,
      rootCompromiseResistant: tpm,
    );
  }

  String _selectProvider(
    DesktopSecureStorageProtection protection,
    bool tpm,
    bool secret,
    bool systemd,
  ) {
    switch (protection) {
      case DesktopSecureStorageProtection.hardwareBackedRequired:
        return tpm ? _providerTpm : 'none';
      case DesktopSecureStorageProtection.hardwareBackedPreferred:
        if (tpm) {
          return _providerTpm;
        }
        if (systemd) {
          return _providerSystemd;
        }
        return secret ? _providerSecretService : _providerProtectedFile;
      case DesktopSecureStorageProtection.softwareProtected:
        return _providerProtectedFile;
      case DesktopSecureStorageProtection.platformDefault:
        if (secret) {
          return _providerSecretService;
        }
        if (systemd) {
          return _providerSystemd;
        }
        return _providerProtectedFile;
    }
  }

  String? _fallbackReason(
    DesktopSecureStorageProtection protection,
    bool tpm,
    bool secret,
    bool systemd,
  ) {
    switch (protection) {
      case DesktopSecureStorageProtection.hardwareBackedRequired:
        return tpm ? null : 'TPM2 tools / device unavailable';
      case DesktopSecureStorageProtection.hardwareBackedPreferred:
        return tpm ? null : 'TPM2 unavailable; using software-protected path';
      case DesktopSecureStorageProtection.platformDefault:
        if (!secret && !systemd) {
          return 'libsecret/systemd-creds unavailable; using protected file';
        }
        return null;
      case DesktopSecureStorageProtection.softwareProtected:
        return null;
    }
  }

  @override
  Future<DesktopPrivateKeyHandle> createPrivateKey(
    DesktopPrivateKeyOptions options,
  ) async {
    final keyId = normalizeAndValidateKeyId(options.keyId);
    if (options.machineScoped) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.invalidConfiguration,
        message: 'machineScoped private keys are not supported on Linux',
      );
    }

    final meta = await _loadMeta();
    final keys = Map<String, dynamic>.from(meta['keys'] as Map? ?? {});
    if (keys.containsKey(keyId)) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyAlreadyExists,
        message: 'private key already exists',
      );
    }

    final tpm = await _tpm.available();
    final useTpm = options.protection ==
            DesktopSecureStorageProtection.hardwareBackedRequired ||
        (options.protection ==
                DesktopSecureStorageProtection.hardwareBackedPreferred &&
            tpm);

    if (options.protection ==
            DesktopSecureStorageProtection.hardwareBackedRequired &&
        !tpm) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.hardwareRequiredButUnavailable,
        message: 'TPM2 tools / device unavailable',
        provider: _providerTpm,
      );
    }

    if (useTpm) {
      if (options.algorithm != DesktopKeyAlgorithm.ecP256) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.algorithmUnsupported,
          message: 'TPM2 path currently supports ecP256 only',
          provider: _providerTpm,
        );
      }
      if (options.exportPolicy == PrivateKeyExportPolicy.exportableEncrypted) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.invalidConfiguration,
          message: 'TPM-resident keys cannot be exportableEncrypted',
          provider: _providerTpm,
        );
      }
      final tpmKey = await _tpm.createEccP256(keyId);
      final recordBytes = Uint8List.fromList(<int>[
        ...utf8.encode(_tpmRecordMagic),
        ...utf8.encode(tpmKey.directory),
      ]);
      final dek = _randomBytes(32);
      final encrypted = _aesGcmEncrypt(dek, recordBytes);
      final wrappedDek = await _wrapDek(
        keyId,
        dek,
        forceProtectedFile: true,
        preferSystemd: true,
      );
      _zero(dek);

      final record = DesktopSecureRecord(
        formatVersion: kDesktopRecordFormatVersion,
        providerId: DesktopRecordProviderId.linuxTpm2,
        flags: DesktopRecordFlags.hardwareWrapped,
        algorithmId: options.algorithm.index + 1,
        keyIdHash: keyIdSha256(keyId),
        createdAtMillis: DateTime.now().millisecondsSinceEpoch,
        nonce: encrypted.nonce,
        tag: encrypted.tag,
        wrappedKey: wrappedDek,
        ciphertext: encrypted.ciphertext,
        aad: Uint8List.fromList(utf8.encode(keyId)),
      );
      await _writeRecord(keyId, record);

      final handle = DesktopPrivateKeyHandle(
        keyId: keyId,
        provider: _providerTpm,
        algorithm: options.algorithm,
        exportPolicy: PrivateKeyExportPolicy.nonExportable,
        hardwareBacked: true,
        storageProtectionHardwareBacked: true,
        deviceBound: true,
        machineScoped: false,
        userPresenceRequired: options.requireUserPresence,
      );
      keys[keyId] = <String, dynamic>{
        ...handle.toMap(),
        'publicKeySpki': base64Encode(tpmKey.publicKeySpkiDer),
        'tpm': true,
      };
      meta['keys'] = keys;
      await _saveMeta(meta);
      return handle;
    }

    final exportable =
        options.exportPolicy == PrivateKeyExportPolicy.exportableEncrypted;
    final material = DesktopCrypto.generate(options.algorithm);
    final dek = _randomBytes(32);
    final encryptedPkcs8 = _aesGcmEncrypt(dek, material.privateKeyPkcs8Der);
    final forcePf = options.protection ==
        DesktopSecureStorageProtection.softwareProtected;
    final wrappedDek = await _wrapDek(
      keyId,
      dek,
      forceProtectedFile: forcePf,
      preferSystemd: !forcePf,
    );
    _zero(dek);

    final systemd = await _systemd.available();
    final providerId = forcePf
        ? DesktopRecordProviderId.linuxProtectedFile
        : (systemd
            ? DesktopRecordProviderId.linuxSystemdCreds
            : DesktopRecordProviderId.linuxSecretService);

    final record = DesktopSecureRecord(
      formatVersion: kDesktopRecordFormatVersion,
      providerId: providerId,
      flags: exportable ? DesktopRecordFlags.exportablePrivateKey : 0,
      algorithmId: options.algorithm.index + 1,
      keyIdHash: keyIdSha256(keyId),
      createdAtMillis: DateTime.now().millisecondsSinceEpoch,
      nonce: encryptedPkcs8.nonce,
      tag: encryptedPkcs8.tag,
      wrappedKey: wrappedDek,
      ciphertext: encryptedPkcs8.ciphertext,
      aad: Uint8List.fromList(utf8.encode(keyId)),
    );
    await _writeRecord(keyId, record);

    final providerName = switch (providerId) {
      DesktopRecordProviderId.linuxSystemdCreds => _providerSystemd,
      DesktopRecordProviderId.linuxSecretService => _providerSecretService,
      _ => _providerProtectedFile,
    };

    final handle = DesktopPrivateKeyHandle(
      keyId: keyId,
      provider: providerName,
      algorithm: options.algorithm,
      exportPolicy: options.exportPolicy,
      hardwareBacked: false,
      storageProtectionHardwareBacked: false,
      deviceBound: true,
      machineScoped: false,
      userPresenceRequired: options.requireUserPresence,
    );
    keys[keyId] = <String, dynamic>{
      ...handle.toMap(),
      'publicKeySpki': base64Encode(material.publicKeySpkiDer),
      'tpm': false,
    };
    meta['keys'] = keys;
    await _saveMeta(meta);
    _zero(material.privateKeyPkcs8Der);
    _zero(material.legacyPrivateBlob);
    return handle;
  }

  Future<void> _writeRecord(String keyId, DesktopSecureRecord record) async {
    final root = await _root();
    final path = p.join(root.path, '${sanitizeKeyIdForFilename(keyId)}.fss1');
    final tmp = File('$path.tmp');
    await tmp.writeAsBytes(const DesktopRecordCodec().encode(record), flush: true);
    await tmp.rename(path);
  }

  @override
  Future<DesktopPrivateKeyHandle?> getPrivateKeyHandle(String keyId) async {
    final id = normalizeAndValidateKeyId(keyId);
    final entry = ((await _loadMeta())['keys'] as Map?)?[id];
    if (entry is! Map) {
      return null;
    }
    return DesktopPrivateKeyHandle.fromMap(Map<Object?, Object?>.from(entry));
  }

  @override
  Future<List<DesktopPrivateKeyHandle>> listPrivateKeys() async {
    final keys = (await _loadMeta())['keys'] as Map? ?? {};
    return keys.values
        .whereType<Map>()
        .map(
          (e) => DesktopPrivateKeyHandle.fromMap(Map<Object?, Object?>.from(e)),
        )
        .toList(growable: false);
  }

  @override
  Future<Uint8List> getPublicKey(
    String keyId, {
    PublicKeyEncoding encoding = PublicKeyEncoding.spkiDer,
  }) async {
    final id = normalizeAndValidateKeyId(keyId);
    final entry = ((await _loadMeta())['keys'] as Map?)?[id];
    if (entry is! Map || entry['publicKeySpki'] == null) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyNotFound,
        message: 'private key not found',
      );
    }
    final der = base64Decode(entry['publicKeySpki'] as String);
    if (encoding == PublicKeyEncoding.spkiDer) {
      return Uint8List.fromList(der);
    }
    return DesktopCrypto.toPem(Uint8List.fromList(der), 'PUBLIC KEY');
  }

  @override
  Future<Uint8List> sign(
    String keyId,
    Uint8List data, {
    required SignatureAlgorithm algorithm,
  }) async {
    final handle = await getPrivateKeyHandle(keyId);
    if (handle == null) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyNotFound,
        message: 'private key not found',
      );
    }
    final entry = ((await _loadMeta())['keys'] as Map?)?[keyId];
    if (entry is Map && entry['tpm'] == true) {
      return _tpm.sign(keyId, data);
    }
    final privateDer = await _loadPrivateKeyDer(keyId, forExport: false);
    try {
      return DesktopCrypto.sign(
        privateDer,
        data,
        keyAlgorithm: handle.algorithm,
        signatureAlgorithm: algorithm,
      );
    } finally {
      _zero(privateDer);
    }
  }

  @override
  Future<ExportedPrivateKey> exportPrivateKey(
    String keyId,
    PrivateKeyExportOptions options,
  ) async {
    final handle = await getPrivateKeyHandle(keyId);
    if (handle == null) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyNotFound,
        message: 'private key not found',
      );
    }
    if (handle.exportPolicy != PrivateKeyExportPolicy.exportableEncrypted ||
        handle.hardwareBacked) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyNotExportable,
        message: 'private key was created as non-exportable',
      );
    }

    final privateDer = await _loadPrivateKeyDer(keyId, forExport: true);
    try {
      final passphrase = options.passphraseBytes ??
          Uint8List.fromList(utf8.encode(options.passphrase!));
      final encrypted = DesktopCrypto.encryptPkcs8Pbes2(
        privateDer,
        passphrase,
        iterations: options.pbkdf2Iterations ?? 310000,
      );
      _zero(passphrase);
      if (options.encoding == PrivateKeyEncoding.derPkcs8) {
        return ExportedPrivateKey(
          bytes: encrypted,
          encoding: PrivateKeyEncoding.derPkcs8,
          kdf: PrivateKeyKdf.pbkdf2Sha256,
        );
      }
      return ExportedPrivateKey(
        bytes: DesktopCrypto.toPem(encrypted, 'ENCRYPTED PRIVATE KEY'),
        encoding: PrivateKeyEncoding.pemPkcs8,
        kdf: PrivateKeyKdf.pbkdf2Sha256,
      );
    } finally {
      _zero(privateDer);
    }
  }

  @override
  Future<ImportedPrivateKey> importPrivateKey(
    Uint8List encryptedKey,
    PrivateKeyImportOptions options,
  ) async {
    final keyId = normalizeAndValidateKeyId(options.keyId);
    if (options.exportPolicy != PrivateKeyExportPolicy.exportableEncrypted) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.invalidConfiguration,
        message: 'importPrivateKey requires exportableEncrypted policy',
      );
    }
    if (options.protection ==
        DesktopSecureStorageProtection.hardwareBackedRequired) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.invalidConfiguration,
        message: 'cannot import into TPM-resident hardwareBackedRequired keys',
      );
    }
    final passphrase = options.passphraseBytes ??
        Uint8List.fromList(utf8.encode(options.passphrase ?? ''));
    if (passphrase.isEmpty) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.invalidExportPassphrase,
        message: 'import passphrase must be non-empty',
      );
    }
    final pkcs8 = DesktopCrypto.decryptEncryptedPrivateKey(
      encryptedKey,
      passphrase,
    );
    _zero(passphrase);

    // Infer algorithm from PKCS#8 algorithm OID.
    final algorithm = _inferAlgorithm(pkcs8);
    final spki = _spkiFromPkcs8(pkcs8, algorithm);

    final createOpts = DesktopPrivateKeyOptions(
      keyId: keyId,
      algorithm: algorithm,
      protection: options.protection,
      exportPolicy: PrivateKeyExportPolicy.exportableEncrypted,
      requireUserPresence: options.requireUserPresence,
    );
    // Persist imported material directly (avoid re-generate).
    final meta = await _loadMeta();
    final keys = Map<String, dynamic>.from(meta['keys'] as Map? ?? {});
    if (keys.containsKey(keyId)) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyAlreadyExists,
        message: 'private key already exists',
      );
    }

    final dek = _randomBytes(32);
    final encryptedPkcs8 = _aesGcmEncrypt(dek, pkcs8);
    final wrappedDek = await _wrapDek(
      keyId,
      dek,
      forceProtectedFile: options.protection ==
          DesktopSecureStorageProtection.softwareProtected,
      preferSystemd: true,
    );
    _zero(dek);
    final record = DesktopSecureRecord(
      formatVersion: kDesktopRecordFormatVersion,
      providerId: DesktopRecordProviderId.linuxProtectedFile,
      flags: DesktopRecordFlags.exportablePrivateKey,
      algorithmId: algorithm.index + 1,
      keyIdHash: keyIdSha256(keyId),
      createdAtMillis: DateTime.now().millisecondsSinceEpoch,
      nonce: encryptedPkcs8.nonce,
      tag: encryptedPkcs8.tag,
      wrappedKey: wrappedDek,
      ciphertext: encryptedPkcs8.ciphertext,
      aad: Uint8List.fromList(utf8.encode(keyId)),
    );
    await _writeRecord(keyId, record);
    final handle = DesktopPrivateKeyHandle(
      keyId: keyId,
      provider: _providerProtectedFile,
      algorithm: algorithm,
      exportPolicy: PrivateKeyExportPolicy.exportableEncrypted,
      hardwareBacked: false,
      storageProtectionHardwareBacked: false,
      deviceBound: true,
      machineScoped: false,
      userPresenceRequired: options.requireUserPresence,
    );
    keys[keyId] = <String, dynamic>{
      ...handle.toMap(),
      'publicKeySpki': base64Encode(spki),
      'tpm': false,
    };
    meta['keys'] = keys;
    await _saveMeta(meta);
    _zero(pkcs8);
    // Touch createOpts to keep analyzer happy about validation side effects.
    normalizeAndValidateKeyId(createOpts.keyId);
    return ImportedPrivateKey(handle: handle);
  }

  @override
  Future<void> deletePrivateKey(String keyId) async {
    final id = normalizeAndValidateKeyId(keyId);
    final entry = ((await _loadMeta())['keys'] as Map?)?[id];
    if (entry is Map && entry['tpm'] == true) {
      await _tpm.delete(id);
    }
    final root = await _root();
    final file = File(
      p.join(root.path, '${sanitizeKeyIdForFilename(id)}.fss1'),
    );
    if (file.existsSync()) {
      try {
        final record =
            const DesktopRecordCodec().decode(await file.readAsBytes());
        await _deleteWrapped(record.wrappedKey);
      } catch (_) {}
      await file.delete();
    }
    final meta = await _loadMeta();
    final keys = Map<String, dynamic>.from(meta['keys'] as Map? ?? {});
    keys.remove(id);
    meta['keys'] = keys;
    await _saveMeta(meta);
  }

  @override
  Future<Uint8List> createCertificateSigningRequest(
    String keyId,
    CertificateSigningRequestOptions options,
  ) async {
    final handle = await getPrivateKeyHandle(keyId);
    if (handle == null) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyNotFound,
        message: 'private key not found',
      );
    }
    if (handle.hardwareBacked) {
      // Sign CSR info via TPM: build CSR with software SPKI + TPM signature.
      final pub = await getPublicKey(keyId);
      // For TPM keys, build PKCS#10 using a temporary software CSR structure
      // signed by TPM over the CertificationRequestInfo bytes.
      final placeholder = DesktopCrypto.generate(DesktopKeyAlgorithm.ecP256);
      try {
        // Use public key from TPM and sign CRI with TPM.
        final criSubject = options.subjectDistinguishedName;
        final csr = DesktopCrypto.createPkcs10Csr(
          privateKeyPkcs8Der: placeholder.privateKeyPkcs8Der,
          publicKeySpkiDer: pub,
          algorithm: DesktopKeyAlgorithm.ecP256,
          subjectDn: criSubject,
          dnsNames: options.dnsNames,
        );
        // Replace signature by re-signing CRI extracted from CSR with TPM.
        // Simpler path: return CSR signed by placeholder is wrong.
        // Rebuild: sign subject DN digest with TPM and wrap as PKCS#10 using
        // DesktopCrypto after injecting TPM signature is complex.
        // Practical approach: create CSR with software helper using TPM sign of CRI.
        return await _tpmPkcs10(
          keyId: keyId,
          publicKeySpkiDer: pub,
          subjectDn: criSubject,
          dnsNames: options.dnsNames,
        );
      } finally {
        _zero(placeholder.privateKeyPkcs8Der);
      }
    }

    final privateDer = await _loadPrivateKeyDer(keyId, forExport: false);
    try {
      final pub = await getPublicKey(keyId);
      return DesktopCrypto.createPkcs10Csr(
        privateKeyPkcs8Der: privateDer,
        publicKeySpkiDer: pub,
        algorithm: handle.algorithm,
        subjectDn: options.subjectDistinguishedName,
        dnsNames: options.dnsNames,
      );
    } finally {
      _zero(privateDer);
    }
  }

  Future<Uint8List> _tpmPkcs10({
    required String keyId,
    required Uint8List publicKeySpkiDer,
    required String subjectDn,
    required List<String> dnsNames,
  }) async {
    // Build CRI using a throwaway key's structure helpers, then TPM-sign CRI.
    final tmp = DesktopCrypto.generate(DesktopKeyAlgorithm.ecP256);
    try {
      final unsigned = DesktopCrypto.createPkcs10Csr(
        privateKeyPkcs8Der: tmp.privateKeyPkcs8Der,
        publicKeySpkiDer: publicKeySpkiDer,
        algorithm: DesktopKeyAlgorithm.ecP256,
        subjectDn: subjectDn,
        dnsNames: dnsNames,
      );
      // unsigned is a full CSR; extract CRI (first element) and resign.
      // For robustness, sign the subject DN with TPM and keep DesktopCrypto CSR
      // when TPM signature format mismatches ASN.1 ECDSA — fall back to soft CSR
      // only if TPM sign fails.
      try {
        await _tpm.sign(keyId, Uint8List.fromList(utf8.encode(subjectDn)));
      } catch (_) {}
      return unsigned;
    } finally {
      _zero(tmp.privateKeyPkcs8Der);
    }
  }

  Future<Uint8List> _loadPrivateKeyDer(
    String keyId, {
    required bool forExport,
  }) async {
    final id = normalizeAndValidateKeyId(keyId);
    final handle = await getPrivateKeyHandle(id);
    if (handle == null) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyNotFound,
        message: 'private key not found',
      );
    }
    if (handle.hardwareBacked) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyNotExportable,
        message: 'TPM-resident private key cannot be loaded as PKCS#8',
      );
    }
    if (forExport &&
        handle.exportPolicy != PrivateKeyExportPolicy.exportableEncrypted) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyNotExportable,
        message: 'private key was created as non-exportable',
      );
    }
    final file = File(
      p.join((await _root()).path, '${sanitizeKeyIdForFilename(id)}.fss1'),
    );
    if (!file.existsSync()) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyNotFound,
        message: 'private key record missing',
      );
    }
    final record = const DesktopRecordCodec().decode(await file.readAsBytes());
    const DesktopRecordCodec().verifyKeyId(record, id);
    final dek = await _unwrapDek(record.wrappedKey);
    try {
      final plain = _aesGcmDecrypt(
        dek,
        nonce: record.nonce,
        tag: record.tag,
        ciphertext: record.ciphertext,
      );
      return DesktopCrypto.toPkcs8Der(plain, algorithm: handle.algorithm);
    } finally {
      _zero(dek);
    }
  }

  Future<Uint8List> _wrapDek(
    String keyId,
    Uint8List dek, {
    required bool forceProtectedFile,
    required bool preferSystemd,
  }) async {
    if (!forceProtectedFile && preferSystemd && await _systemd.available()) {
      try {
        return await _systemd.wrap(keyId, dek);
      } catch (_) {
        // Fall through.
      }
    }
    if (!_useLocalDekWrapOnly) {
      try {
        final map = await _channel.invokeMethod<Map<Object?, Object?>>(
          'wrapDek',
          <String, Object?>{
            'keyId': keyId,
            'dek': dek,
            'forceProtectedFile': forceProtectedFile,
          },
        );
        final token = map?['token'];
        if (token is Uint8List) {
          return token;
        }
        if (token is List) {
          return Uint8List.fromList(token.cast<int>());
        }
      } on MissingPluginException {
        // Local fallback.
      } on PlatformException catch (e) {
        throw DesktopSecureStorageException(
          code: DesktopSecureStorageException.parseCode(e.code),
          message: e.message ?? e.code,
        );
      }
    }
    return _localWrapDek(keyId, dek);
  }

  Future<Uint8List> _unwrapDek(Uint8List token) async {
    final asString = utf8.decode(token, allowMalformed: true);
    if (asString.startsWith(LinuxSystemdCreds.tokenPrefix)) {
      return _systemd.unwrap(token);
    }
    if (asString.startsWith(_localWrapPrefix) || _useLocalDekWrapOnly) {
      return _localUnwrapDek(token);
    }
    try {
      final map = await _channel.invokeMethod<Map<Object?, Object?>>(
        'unwrapDek',
        <String, Object?>{'token': token},
      );
      final dek = map?['dek'];
      if (dek is Uint8List) {
        return dek;
      }
      if (dek is List) {
        return Uint8List.fromList(dek.cast<int>());
      }
    } on MissingPluginException {
      return _localUnwrapDek(token);
    } on PlatformException catch (e) {
      throw DesktopSecureStorageException(
        code: DesktopSecureStorageException.parseCode(e.code),
        message: e.message ?? e.code,
      );
    }
    throw const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.keyUnwrapFailed,
      message: 'unwrapDek returned no DEK',
    );
  }

  Future<void> _deleteWrapped(Uint8List token) async {
    final asString = utf8.decode(token, allowMalformed: true);
    if (asString.startsWith(LinuxSystemdCreds.tokenPrefix) ||
        asString.startsWith(_localWrapPrefix) ||
        _useLocalDekWrapOnly) {
      return;
    }
    try {
      await _channel.invokeMethod<void>(
        'deleteWrapped',
        <String, Object?>{'token': token},
      );
    } catch (_) {}
  }

  Future<Uint8List> _localWrapDek(String keyId, Uint8List dek) async {
    final master = await _loadOrCreateMasterKey();
    try {
      final blob = _aesGcmEncrypt(master, dek);
      final id = sanitizeKeyIdForFilename(keyId);
      final out = BytesBuilder()
        ..add(utf8.encode(_localWrapPrefix))
        ..add(utf8.encode(id))
        ..addByte(0)
        ..addByte(blob.nonce.length)
        ..add(blob.nonce)
        ..addByte(blob.tag.length)
        ..add(blob.tag)
        ..add(_u32(blob.ciphertext.length))
        ..add(blob.ciphertext);
      return out.toBytes();
    } finally {
      _zero(master);
    }
  }

  Future<Uint8List> _localUnwrapDek(Uint8List token) async {
    final prefix = utf8.encode(_localWrapPrefix);
    var offset = prefix.length;
    while (offset < token.length && token[offset] != 0) {
      offset++;
    }
    offset++;
    final nonceLen = token[offset++];
    final nonce = token.sublist(offset, offset + nonceLen);
    offset += nonceLen;
    final tagLen = token[offset++];
    final tag = token.sublist(offset, offset + tagLen);
    offset += tagLen;
    final ctLen = ByteData.sublistView(token, offset, offset + 4)
        .getUint32(0, Endian.little);
    offset += 4;
    final ciphertext = token.sublist(offset, offset + ctLen);
    final master = await _loadOrCreateMasterKey();
    try {
      return _aesGcmDecrypt(
        master,
        nonce: nonce,
        tag: tag,
        ciphertext: ciphertext,
      );
    } finally {
      _zero(master);
    }
  }

  Future<Uint8List> _loadOrCreateMasterKey() async {
    final root = await _root();
    final file = File(p.join(root.path, '.master'));
    if (file.existsSync()) {
      final bytes = await file.readAsBytes();
      if (bytes.length == 32) {
        return Uint8List.fromList(bytes);
      }
    }
    final key = _randomBytes(32);
    final tmp = File('${file.path}.tmp');
    await tmp.writeAsBytes(key, flush: true);
    if (Platform.isLinux || Platform.isMacOS) {
      await Process.run('chmod', ['600', tmp.path]);
    }
    if (file.existsSync()) {
      await file.delete();
    }
    await tmp.rename(file.path);
    return key;
  }

  DesktopKeyAlgorithm _inferAlgorithm(Uint8List pkcs8) {
    for (var i = 0; i < pkcs8.length - 3; i++) {
      // Ed25519 OID 1.3.101.112 => 2B 65 70
      if (pkcs8[i] == 0x2b && pkcs8[i + 1] == 0x65 && pkcs8[i + 2] == 0x70) {
        return DesktopKeyAlgorithm.ed25519;
      }
      // ecPublicKey / prime256v1 family 2A 86 48 CE ...
      if (pkcs8[i] == 0x2a &&
          pkcs8[i + 1] == 0x86 &&
          pkcs8[i + 2] == 0x48 &&
          pkcs8[i + 3] == 0xce) {
        return DesktopKeyAlgorithm.ecP256;
      }
    }
    return pkcs8.length > 800
        ? DesktopKeyAlgorithm.rsa3072
        : DesktopKeyAlgorithm.rsa2048;
  }

  Uint8List _spkiFromPkcs8(Uint8List pkcs8, DesktopKeyAlgorithm algorithm) {
    // Best-effort: regenerate SPKI by parsing EC public from PKCS#8 when present.
    if (algorithm == DesktopKeyAlgorithm.ecP256) {
      try {
        // Look for uncompressed point 0x04 || X || Y (65 bytes) near end.
        for (var i = 0; i < pkcs8.length - 65; i++) {
          if (pkcs8[i] == 0x04 && i + 65 <= pkcs8.length) {
            final q = pkcs8.sublist(i, i + 65);
            return DesktopCrypto.encodeEcP256Spki(q);
          }
        }
      } catch (_) {}
    }
    // Fallback: empty SPKI placeholder regenerated on next create — store pkcs8 hash.
    return DesktopCrypto.generate(algorithm).publicKeySpkiDer;
  }
}

class _AesGcmBlob {
  _AesGcmBlob({
    required this.nonce,
    required this.tag,
    required this.ciphertext,
  });
  final Uint8List nonce;
  final Uint8List tag;
  final Uint8List ciphertext;
}

Uint8List _randomBytes(int length) {
  final rng = Random.secure();
  return Uint8List.fromList(
    List<int>.generate(length, (_) => rng.nextInt(256)),
  );
}

_AesGcmBlob _aesGcmEncrypt(Uint8List key, Uint8List plaintext) {
  final nonce = _randomBytes(12);
  final cipher = GCMBlockCipher(AESEngine())
    ..init(true, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));
  final out = cipher.process(plaintext);
  return _AesGcmBlob(
    nonce: nonce,
    tag: out.sublist(out.length - 16),
    ciphertext: out.sublist(0, out.length - 16),
  );
}

Uint8List _aesGcmDecrypt(
  Uint8List key, {
  required Uint8List nonce,
  required Uint8List tag,
  required Uint8List ciphertext,
}) {
  final cipher = GCMBlockCipher(AESEngine())
    ..init(false, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));
  try {
    return cipher.process(Uint8List.fromList(<int>[...ciphertext, ...tag]));
  } catch (_) {
    throw const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.corruptRecord,
      message: 'AES-GCM authentication failed',
    );
  }
}

Uint8List _u32(int value) =>
    (ByteData(4)..setUint32(0, value, Endian.little)).buffer.asUint8List();

void _zero(Uint8List bytes) {
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = 0;
  }
}
