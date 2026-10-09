import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:flutter_secure_storage_windows/src/desktop/windows_der.dart';
import 'package:flutter_secure_storage_windows/src/desktop/windows_tpm_key_backend.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:win32/win32.dart';

/// Windows [DesktopPrivateKeyManager].
///
/// Non-exportable keys that request hardware are created inside the TPM
/// through the Microsoft Platform Crypto Provider and never leave it. Other
/// keys are software key material in DPAPI-wrapped FSS1 records.
class WindowsDesktopKeyManager extends DesktopPrivateKeyManager {
  /// Creates a Windows desktop key manager.
  WindowsDesktopKeyManager({
    Directory? storageRoot,
    bool? tpmAvailableOverride,
    WindowsTpmKeyBackend? tpmBackend,
  })  : _storageRoot = storageRoot,
        _tpmAvailableOverride = tpmAvailableOverride,
        _tpm = tpmBackend ?? NcryptTpmKeyBackend();

  final Directory? _storageRoot;
  final bool? _tpmAvailableOverride;
  final WindowsTpmKeyBackend _tpm;
  bool? _tpmProbe;

  static const _metaFile = 'keys.json';
  static const _metaNcryptKeyName = 'ncryptKeyName';
  static const _providerDpapi = 'windows_dpapi';
  static const _providerPlatformCrypto = 'MS_PLATFORM_CRYPTO_PROVIDER';
  static const _providerSoftwareCng = 'Microsoft Software Key Storage Provider';

  Future<Directory> _root() async {
    if (_storageRoot != null) {
      await _storageRoot!.create(recursive: true);
      return _storageRoot!;
    }
    final local = Platform.environment['LOCALAPPDATA'];
    if (local != null && local.isNotEmpty) {
      final dir = Directory(
        p.join(local, 'flutter_secure_storage', 'private_keys'),
      );
      await dir.create(recursive: true);
      return dir;
    }
    final support = await getApplicationSupportDirectory();
    final dir = Directory(p.join(support.path, 'private_keys'));
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

  /// True when a TPM 2.0 is reachable through the Microsoft Platform Crypto
  /// Provider. The result is cached for the life of this manager.
  bool probeTpm() {
    if (_tpmAvailableOverride != null) {
      return _tpmAvailableOverride!;
    }
    return _tpmProbe ??= _tpm.probe();
  }

  @override
  Future<DesktopSecureStorageCapabilities> getCapabilities({
    DesktopSecureStorageProtection protection =
        DesktopSecureStorageProtection.platformDefault,
  }) async {
    final tpm = probeTpm();
    final providers = <String>[
      _providerDpapi,
      _providerSoftwareCng,
      if (tpm) _providerPlatformCrypto,
    ];

    var selected = _providerDpapi;
    String? fallback;
    var storageHw = false;
    var privateHw = false;

    switch (protection) {
      case DesktopSecureStorageProtection.hardwareBackedRequired:
        selected = tpm ? _providerPlatformCrypto : 'none';
        storageHw = tpm;
        privateHw = tpm;
      case DesktopSecureStorageProtection.hardwareBackedPreferred:
        if (tpm) {
          selected = _providerPlatformCrypto;
          storageHw = true;
          privateHw = true;
        } else {
          selected = _providerDpapi;
          fallback = 'TPM / platform crypto provider unavailable';
        }
      case DesktopSecureStorageProtection.softwareProtected:
      case DesktopSecureStorageProtection.platformDefault:
        selected = _providerDpapi;
    }

    // TPM-resident keys are non-exportable and cannot be Ed25519.
    final tpmOnly =
        protection == DesktopSecureStorageProtection.hardwareBackedRequired;
    return DesktopSecureStorageCapabilities(
      platform: 'windows',
      availableProviders: providers,
      selectedProvider: selected,
      hardwareAvailable: tpm,
      storageProtectionHardwareBacked: storageHw,
      privateKeyHardwareBacked: privateHw,
      supportsNonExportableKeys: true,
      supportsExportableKeys: !tpmOnly,
      supportsUserPresence: false,
      supportsMachineScope: true,
      supportsCsrGeneration: true,
      supportedAlgorithms: [
        DesktopKeyAlgorithm.rsa2048,
        DesktopKeyAlgorithm.rsa3072,
        DesktopKeyAlgorithm.ecP256,
        if (!tpmOnly) DesktopKeyAlgorithm.ed25519,
      ],
      supportedExportFormats: const [
        PrivateKeyEncoding.pemPkcs8,
        PrivateKeyEncoding.derPkcs8,
      ],
      fallbackReason: fallback,
      sameUserCompromiseResistant: privateHw,
      rootCompromiseResistant: privateHw,
    );
  }

  @override
  Future<DesktopPrivateKeyHandle> createPrivateKey(
    DesktopPrivateKeyOptions options,
  ) async {
    final keyId = normalizeAndValidateKeyId(options.keyId);
    final meta = await _loadMeta();
    final keys = Map<String, dynamic>.from(meta['keys'] as Map? ?? {});
    if (keys.containsKey(keyId)) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyAlreadyExists,
        message: 'private key already exists',
      );
    }

    final caps = await getCapabilities(protection: options.protection);
    final exportable =
        options.exportPolicy == PrivateKeyExportPolicy.exportableEncrypted;
    final hardwareRequired = options.protection ==
        DesktopSecureStorageProtection.hardwareBackedRequired;

    if (hardwareRequired) {
      if (!caps.hardwareAvailable) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.hardwareRequiredButUnavailable,
          message: 'TPM / platform crypto provider unavailable',
          provider: _providerPlatformCrypto,
        );
      }
      if (options.algorithm == DesktopKeyAlgorithm.ed25519) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.algorithmUnsupported,
          message: 'ed25519 is not supported by Windows TPM providers',
          provider: _providerPlatformCrypto,
        );
      }
      if (exportable) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.invalidConfiguration,
          message: 'TPM-resident keys cannot be exportable',
          provider: _providerPlatformCrypto,
        );
      }
      if (options.requireUserPresence) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.invalidConfiguration,
          message: 'user presence is not supported for Windows TPM keys',
          provider: _providerPlatformCrypto,
        );
      }
      return _createTpmKey(keyId, options, meta, keys);
    }

    final tpmEligible = options.protection ==
            DesktopSecureStorageProtection.hardwareBackedPreferred &&
        caps.hardwareAvailable &&
        !exportable &&
        !options.requireUserPresence &&
        options.algorithm != DesktopKeyAlgorithm.ed25519;
    if (tpmEligible) {
      try {
        return await _createTpmKey(keyId, options, meta, keys);
      } on DesktopSecureStorageException {
        // Preferred, not required: fall back to a software key below.
      }
    }

    // Software key material, DPAPI-wrapped in an FSS1 record.
    const claimPrivateHw = false;
    const claimStorageHw = false;

    final pair = DesktopCrypto.generate(options.algorithm);
    final dek = _randomBytes(32);
    final encryptedPkcs8 = _aesGcmEncrypt(dek, pair.privateKeyPkcs8Der);
    final wrappedDek = _dpapiProtect(
      dek,
      machineScoped: options.machineScoped,
    );
    _zero(dek);

    final record = DesktopSecureRecord(
      formatVersion: kDesktopRecordFormatVersion,
      providerId: exportable
          ? DesktopRecordProviderId.windowsSoftwareCng
          : (claimStorageHw
              ? DesktopRecordProviderId.windowsPlatformCrypto
              : DesktopRecordProviderId.windowsDpapi),
      flags: (options.machineScoped ? DesktopRecordFlags.machineScoped : 0) |
          (exportable ? DesktopRecordFlags.exportablePrivateKey : 0) |
          (claimStorageHw ? DesktopRecordFlags.hardwareWrapped : 0) |
          (options.requireUserPresence
              ? DesktopRecordFlags.userPresenceRequired
              : 0),
      algorithmId: options.algorithm.index + 1,
      keyIdHash: keyIdSha256(keyId),
      createdAtMillis: DateTime.now().millisecondsSinceEpoch,
      nonce: encryptedPkcs8.nonce,
      tag: encryptedPkcs8.tag,
      wrappedKey: wrappedDek,
      ciphertext: encryptedPkcs8.ciphertext,
      aad: Uint8List.fromList(utf8.encode(keyId)),
    );

    final root = await _root();
    final path = p.join(root.path, '${sanitizeKeyIdForFilename(keyId)}.fss1');
    final tmp = File('$path.tmp');
    await tmp.writeAsBytes(const DesktopRecordCodec().encode(record), flush: true);
    await tmp.rename(path);

    final handle = DesktopPrivateKeyHandle(
      keyId: keyId,
      provider: exportable
          ? _providerSoftwareCng
          : (claimStorageHw ? _providerPlatformCrypto : _providerDpapi),
      algorithm: options.algorithm,
      exportPolicy: options.exportPolicy,
      hardwareBacked: claimPrivateHw,
      storageProtectionHardwareBacked: claimStorageHw,
      deviceBound: true,
      machineScoped: options.machineScoped,
      userPresenceRequired: options.requireUserPresence,
    );

    keys[keyId] = <String, dynamic>{
      ...handle.toMap(),
      'publicKeySpki': base64Encode(pair.publicKeySpkiDer),
    };
    meta['keys'] = keys;
    await _saveMeta(meta);
    _zero(pair.privateKeyPkcs8Der);
    return handle;
  }

  /// Creates [keyId] inside the TPM. Only the provider key name and the
  /// public key are recorded; there is no FSS1 record because no key material
  /// ever reaches this process.
  Future<DesktopPrivateKeyHandle> _createTpmKey(
    String keyId,
    DesktopPrivateKeyOptions options,
    Map<String, dynamic> meta,
    Map<String, dynamic> keys,
  ) async {
    // A random provider name keeps keys from different apps or stores under
    // the same Windows user from colliding in the TPM key namespace.
    final keyName = 'fss-dsk-${_hex(_randomBytes(16))}';
    final spki = _tpm.createKey(
      keyName: keyName,
      algorithm: options.algorithm,
      machineScoped: options.machineScoped,
    );

    final handle = DesktopPrivateKeyHandle(
      keyId: keyId,
      provider: _providerPlatformCrypto,
      algorithm: options.algorithm,
      exportPolicy: PrivateKeyExportPolicy.nonExportable,
      hardwareBacked: true,
      storageProtectionHardwareBacked: true,
      deviceBound: true,
      machineScoped: options.machineScoped,
      userPresenceRequired: false,
    );

    keys[keyId] = <String, dynamic>{
      ...handle.toMap(),
      'publicKeySpki': base64Encode(spki),
      _metaNcryptKeyName: keyName,
    };
    meta['keys'] = keys;
    try {
      await _saveMeta(meta);
    } catch (_) {
      _tpm.deleteKey(keyName: keyName, machineScoped: options.machineScoped);
      rethrow;
    }
    return handle;
  }

  /// Provider key name when [keyId] is TPM-resident, else null.
  Future<({String keyName, DesktopPrivateKeyHandle handle})?> _tpmKey(
    String keyId,
  ) async {
    final id = normalizeAndValidateKeyId(keyId);
    final entry = ((await _loadMeta())['keys'] as Map?)?[id];
    if (entry is! Map) {
      return null;
    }
    final keyName = entry[_metaNcryptKeyName];
    if (keyName is! String || keyName.isEmpty) {
      return null;
    }
    return (
      keyName: keyName,
      handle:
          DesktopPrivateKeyHandle.fromMap(Map<Object?, Object?>.from(entry)),
    );
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
    final tpmKey = await _tpmKey(id);
    // TPM keys read the public key from the TPM itself, so an edited
    // keys.json cannot substitute another device's public key.
    final der = tpmKey != null
        ? _tpm.publicKeySpki(
            keyName: tpmKey.keyName,
            algorithm: tpmKey.handle.algorithm,
            machineScoped: tpmKey.handle.machineScoped,
          )
        : base64Decode(entry['publicKeySpki'] as String);
    if (encoding == PublicKeyEncoding.spkiDer) {
      return Uint8List.fromList(der);
    }
    final pem = '-----BEGIN PUBLIC KEY-----\n'
        '${_pemWrap(base64.encode(der))}'
        '-----END PUBLIC KEY-----\n';
    return Uint8List.fromList(utf8.encode(pem));
  }

  @override
  Future<Uint8List> sign(
    String keyId,
    Uint8List data, {
    required SignatureAlgorithm algorithm,
  }) async {
    final tpmKey = await _tpmKey(keyId);
    if (tpmKey != null) {
      return _tpm.sign(
        keyName: tpmKey.keyName,
        algorithm: tpmKey.handle.algorithm,
        machineScoped: tpmKey.handle.machineScoped,
        data: data,
        signatureAlgorithm: algorithm,
      );
    }
    final privateDer =
        await _loadPrivateKeyDer(keyId, forExport: false);
    try {
      final handle = await getPrivateKeyHandle(keyId);
      if (handle == null) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.keyNotFound,
          message: 'private key not found',
        );
      }
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
    if (handle.exportPolicy != PrivateKeyExportPolicy.exportableEncrypted) {
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
    final passphrase = options.passphraseBytes ??
        Uint8List.fromList(utf8.encode(options.passphrase ?? ''));
    if (passphrase.isEmpty) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.invalidExportPassphrase,
        message: 'import passphrase must be non-empty',
      );
    }
    final pkcs8 =
        DesktopCrypto.decryptEncryptedPrivateKey(encryptedKey, passphrase);
    _zero(passphrase);
    final created = await createPrivateKey(
      DesktopPrivateKeyOptions(
        keyId: keyId,
        algorithm: DesktopKeyAlgorithm.ecP256,
        protection: options.protection,
        exportPolicy: PrivateKeyExportPolicy.exportableEncrypted,
        machineScoped: options.machineScoped,
        requireUserPresence: options.requireUserPresence,
      ),
    );
    // Overwrite generated material with imported PKCS#8.
    final dek = _randomBytes(32);
    final encryptedPkcs8 = _aesGcmEncrypt(dek, pkcs8);
    final wrappedDek = _dpapiProtect(dek, machineScoped: options.machineScoped);
    _zero(dek);
    final record = DesktopSecureRecord(
      formatVersion: kDesktopRecordFormatVersion,
      providerId: DesktopRecordProviderId.windowsSoftwareCng,
      flags: DesktopRecordFlags.exportablePrivateKey |
          (options.machineScoped ? DesktopRecordFlags.machineScoped : 0),
      algorithmId: DesktopKeyAlgorithm.ecP256.index + 1,
      keyIdHash: keyIdSha256(keyId),
      createdAtMillis: DateTime.now().millisecondsSinceEpoch,
      nonce: encryptedPkcs8.nonce,
      tag: encryptedPkcs8.tag,
      wrappedKey: wrappedDek,
      ciphertext: encryptedPkcs8.ciphertext,
      aad: Uint8List.fromList(utf8.encode(keyId)),
    );
    final root = await _root();
    final path = p.join(root.path, '${sanitizeKeyIdForFilename(keyId)}.fss1');
    final tmp = File('$path.tmp');
    await tmp.writeAsBytes(const DesktopRecordCodec().encode(record), flush: true);
    await tmp.rename(path);
    _zero(pkcs8);
    return ImportedPrivateKey(handle: created);
  }

  @override
  Future<void> deletePrivateKey(String keyId) async {
    final id = normalizeAndValidateKeyId(keyId);
    final tpmKey = await _tpmKey(id);
    if (tpmKey != null) {
      // Delete from the TPM first so a failure keeps the record for a retry.
      _tpm.deleteKey(
        keyName: tpmKey.keyName,
        machineScoped: tpmKey.handle.machineScoped,
      );
    }
    final meta = await _loadMeta();
    final keys = Map<String, dynamic>.from(meta['keys'] as Map? ?? {});
    keys.remove(id);
    meta['keys'] = keys;
    await _saveMeta(meta);
    final file = File(
      p.join((await _root()).path, '${sanitizeKeyIdForFilename(id)}.fss1'),
    );
    if (file.existsSync()) {
      await file.delete();
    }
  }

  @override
  Future<Uint8List> createCertificateSigningRequest(
    String keyId,
    CertificateSigningRequestOptions options,
  ) async {
    final tpmKey = await _tpmKey(keyId);
    if (tpmKey != null) {
      final keyAlgorithm = tpmKey.handle.algorithm;
      final requestInfo = WindowsDer.certificationRequestInfo(
        subjectDn: options.subjectDistinguishedName,
        publicKeySpkiDer: await getPublicKey(keyId),
      );
      final scheme = keyAlgorithm == DesktopKeyAlgorithm.ecP256
          ? SignatureAlgorithm.ecdsaSha256
          : SignatureAlgorithm.rsaPkcs1Sha256;
      return WindowsDer.certificationRequest(
        requestInfo: requestInfo,
        signatureAlgorithm:
            WindowsDer.signatureAlgorithmIdentifier(keyAlgorithm, scheme),
        signature: await sign(keyId, requestInfo, algorithm: scheme),
      );
    }
    final privateDer = await _loadPrivateKeyDer(keyId, forExport: false);
    try {
      final handle = await getPrivateKeyHandle(keyId);
      if (handle == null) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.keyNotFound,
          message: 'private key not found',
        );
      }
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
    final dek = _dpapiUnprotect(
      record.wrappedKey,
      machineScoped: handle.machineScoped,
    );
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

  Uint8List _dpapiProtect(Uint8List plain, {required bool machineScoped}) {
    return using((alloc) {
      final pPlain = alloc<Uint8>(plain.length);
      pPlain.asTypedList(plain.length).setAll(0, plain);
      final plainBlob = alloc<CRYPT_INTEGER_BLOB>();
      plainBlob.ref.cbData = plain.length;
      plainBlob.ref.pbData = pPlain;
      final encBlob = alloc<CRYPT_INTEGER_BLOB>();
      final flags = machineScoped ? 0x4 : 0;
      final Win32Result(value: ok, error: error) = CryptProtectData(
        plainBlob,
        null,
        null,
        null,
        flags,
        encBlob,
      );
      if (!ok) {
        throw DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.accessDenied,
          message: 'CryptProtectData failed',
          nativeStatusCode: error.toHRESULT(),
          provider: _providerDpapi,
        );
      }
      try {
        return Uint8List.fromList(
          encBlob.ref.pbData.asTypedList(encBlob.ref.cbData),
        );
      } finally {
        if (encBlob.ref.pbData.address != NULL) {
          LocalFree(HLOCAL(encBlob.ref.pbData));
        }
      }
    });
  }

  Uint8List _dpapiUnprotect(
    Uint8List encrypted, {
    required bool machineScoped,
  }) {
    return using((alloc) {
      final pEnc = alloc<Uint8>(encrypted.length);
      pEnc.asTypedList(encrypted.length).setAll(0, encrypted);
      final encBlob = alloc<CRYPT_INTEGER_BLOB>();
      encBlob.ref.cbData = encrypted.length;
      encBlob.ref.pbData = pEnc;
      final plainBlob = alloc<CRYPT_INTEGER_BLOB>();
      final flags = machineScoped ? 0x4 : 0;
      final Win32Result(value: ok, error: error) = CryptUnprotectData(
        encBlob,
        null,
        null,
        null,
        flags,
        plainBlob,
      );
      if (!ok) {
        throw DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.keyUnwrapFailed,
          message: 'CryptUnprotectData failed',
          nativeStatusCode: error.toHRESULT(),
          provider: _providerDpapi,
        );
      }
      try {
        return Uint8List.fromList(
          plainBlob.ref.pbData.asTypedList(plainBlob.ref.cbData),
        );
      } finally {
        if (plainBlob.ref.pbData.address != NULL) {
          LocalFree(HLOCAL(plainBlob.ref.pbData));
        }
      }
    });
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

Uint8List _randomBytes(int length) =>
    DesktopCryptoBackend.current.randomBytes(length);

String _hex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

_AesGcmBlob _aesGcmEncrypt(Uint8List key, Uint8List plaintext) {
  final nonce = _randomBytes(12);
  final box = DesktopCryptoBackend.current.aes256GcmEncrypt(
    key: key,
    nonce: nonce,
    plaintext: plaintext,
  );
  return _AesGcmBlob(nonce: nonce, tag: box.tag, ciphertext: box.ciphertext);
}

Uint8List _aesGcmDecrypt(
  Uint8List key, {
  required Uint8List nonce,
  required Uint8List tag,
  required Uint8List ciphertext,
}) {
  try {
    return DesktopCryptoBackend.current.aes256GcmDecrypt(
      key: key,
      nonce: nonce,
      ciphertext: ciphertext,
      tag: tag,
    );
  } catch (_) {
    throw const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.corruptRecord,
      message: 'AES-GCM authentication failed',
    );
  }
}



String _pemWrap(String b64) {
  final buffer = StringBuffer();
  for (var i = 0; i < b64.length; i += 64) {
    buffer.writeln(b64.substring(i, min(i + 64, b64.length)));
  }
  return buffer.toString();
}

void _zero(Uint8List bytes) {
  for (var i = 0; i < bytes.length; i++) {
    bytes[i] = 0;
  }
}
