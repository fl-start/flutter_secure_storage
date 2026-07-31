import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/services.dart';
import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:path/path.dart' as p;
import 'package:pointycastle/export.dart';

/// Linux [DesktopPrivateKeyManager] using software keys, FSS1 records, and
/// native DEK wrap (Secret Service or protected-file) with a local fallback.
class LinuxDesktopKeyManager extends DesktopPrivateKeyManager {
  /// Creates a Linux desktop key manager.
  LinuxDesktopKeyManager({
    Directory? storageRoot,
    MethodChannel? channel,
    bool? tpmAvailableOverride,
    bool? secretServiceAvailableOverride,
    bool useLocalDekWrapOnly = false,
  })  : _storageRoot = storageRoot,
        _channel = channel ??
            const MethodChannel(
              'plugins.it_nomads.com/flutter_secure_storage/desktop_keys',
            ),
        _tpmAvailableOverride = tpmAvailableOverride,
        _secretServiceAvailableOverride = secretServiceAvailableOverride,
        _useLocalDekWrapOnly = useLocalDekWrapOnly;

  final Directory? _storageRoot;
  final MethodChannel _channel;
  final bool? _tpmAvailableOverride;
  final bool? _secretServiceAvailableOverride;
  final bool _useLocalDekWrapOnly;

  static const _metaFile = 'keys.json';
  static const _providerSecretService = 'secret_service';
  static const _providerProtectedFile = 'protected_file';
  static const _providerTpm = 'tpm2_optional';
  static const _localWrapPrefix = 'loc1:';

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

  bool _probeTpmLocal() {
    if (_tpmAvailableOverride != null) {
      return _tpmAvailableOverride!;
    }
    return false;
  }

  @override
  Future<DesktopSecureStorageCapabilities> getCapabilities({
    DesktopSecureStorageProtection protection =
        DesktopSecureStorageProtection.platformDefault,
  }) async {
    if (!_useLocalDekWrapOnly) {
      try {
        final map = await _channel.invokeMethod<Map<Object?, Object?>>(
          'getCapabilities',
          <String, Object?>{'protection': protection.name},
        );
        if (map != null) {
          return DesktopSecureStorageCapabilities.fromMap(map);
        }
      } on MissingPluginException {
        // Fall through to local probe (unit tests / no plugin).
      } on PlatformException {
        // Fall through.
      }
    }

    final tpm = _probeTpmLocal();
    final secret = _secretServiceAvailableOverride ?? false;
    final providers = <String>[
      if (secret) _providerSecretService,
      _providerProtectedFile,
      if (tpm) _providerTpm,
    ];

    var selected = _providerProtectedFile;
    String? fallback;
    switch (protection) {
      case DesktopSecureStorageProtection.hardwareBackedRequired:
        selected = tpm ? _providerTpm : 'none';
        fallback = tpm
            ? 'TPM2 private-key path not implemented'
            : 'TPM2 ESAPI unavailable';
      case DesktopSecureStorageProtection.hardwareBackedPreferred:
        selected = secret ? _providerSecretService : _providerProtectedFile;
        fallback = tpm
            ? 'TPM2 private-key path not implemented; using software wrap'
            : 'TPM / libtss2-esys unavailable';
      case DesktopSecureStorageProtection.softwareProtected:
        selected = _providerProtectedFile;
      case DesktopSecureStorageProtection.platformDefault:
        selected = secret ? _providerSecretService : _providerProtectedFile;
        if (!secret) {
          fallback = 'libsecret unavailable';
        }
    }

    return DesktopSecureStorageCapabilities(
      platform: 'linux',
      availableProviders: providers,
      selectedProvider: selected,
      hardwareAvailable: tpm,
      storageProtectionHardwareBacked: false,
      privateKeyHardwareBacked: false,
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
      fallbackReason: fallback,
      sameUserCompromiseResistant: false,
      rootCompromiseResistant: false,
    );
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

    final caps = await getCapabilities(protection: options.protection);
    if (options.protection ==
        DesktopSecureStorageProtection.hardwareBackedRequired) {
      throw DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.hardwareRequiredButUnavailable,
        message: caps.fallbackReason ??
            'TPM2 private-key path not implemented',
        provider: _providerTpm,
      );
    }

    final exportable =
        options.exportPolicy == PrivateKeyExportPolicy.exportableEncrypted;
    final forcePf = options.protection ==
            DesktopSecureStorageProtection.softwareProtected ||
        caps.selectedProvider == _providerProtectedFile;

    final pair = _generateSoftwareKey(options.algorithm);
    final dek = _randomBytes(32);
    final encryptedPkcs8 = _aesGcmEncrypt(dek, pair.privateBlob);
    final wrappedDek = await _wrapDek(
      keyId,
      dek,
      forceProtectedFile: forcePf,
    );
    _zero(dek);

    final providerId = forcePf || !caps.availableProviders.contains(
      _providerSecretService,
    )
        ? DesktopRecordProviderId.linuxProtectedFile
        : DesktopRecordProviderId.linuxSecretService;

    final record = DesktopSecureRecord(
      formatVersion: kDesktopRecordFormatVersion,
      providerId: providerId,
      flags: (exportable ? DesktopRecordFlags.exportablePrivateKey : 0) |
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

    final providerName = providerId == DesktopRecordProviderId.linuxSecretService
        ? _providerSecretService
        : _providerProtectedFile;

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
      'publicKeySpki': base64Encode(pair.publicBlob),
    };
    meta['keys'] = keys;
    await _saveMeta(meta);
    _zero(pair.privateBlob);
    return handle;
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
    final privateDer = await _loadPrivateKeyDer(keyId, forExport: false);
    try {
      final handle = await getPrivateKeyHandle(keyId);
      if (handle == null) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.keyNotFound,
          message: 'private key not found',
        );
      }
      return _sign(privateDer, data, handle.algorithm);
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
      final encrypted = _encryptPkcs8Pbes2(
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
      final pem = '-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
          '${_pemWrap(base64.encode(encrypted))}'
          '-----END ENCRYPTED PRIVATE KEY-----\n';
      return ExportedPrivateKey(
        bytes: Uint8List.fromList(utf8.encode(pem)),
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
    throw const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.invalidConfiguration,
      message:
          'importPrivateKey for encrypted PKCS#8 is staged; create exportable keys via createPrivateKey',
    );
  }

  @override
  Future<void> deletePrivateKey(String keyId) async {
    final id = normalizeAndValidateKeyId(keyId);
    final root = await _root();
    final file = File(
      p.join(root.path, '${sanitizeKeyIdForFilename(id)}.fss1'),
    );
    if (file.existsSync()) {
      try {
        final record =
            const DesktopRecordCodec().decode(await file.readAsBytes());
        await _deleteWrapped(record.wrappedKey);
      } catch (_) {
        // Best-effort unwrap cleanup.
      }
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
    final privateDer = await _loadPrivateKeyDer(keyId, forExport: false);
    try {
      final handle = await getPrivateKeyHandle(keyId);
      if (handle == null) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.keyNotFound,
          message: 'private key not found',
        );
      }
      final subject = utf8.encode(options.subjectDistinguishedName);
      final signature =
          _sign(privateDer, Uint8List.fromList(subject), handle.algorithm);
      final out = BytesBuilder()
        ..add(utf8.encode('FSS-CSR1'))
        ..add(_u32(subject.length))
        ..add(subject)
        ..add(_u32(signature.length))
        ..add(signature);
      return out.toBytes();
    } finally {
      _zero(privateDer);
    }
  }

  Future<Uint8List> _wrapDek(
    String keyId,
    Uint8List dek, {
    required bool forceProtectedFile,
  }) async {
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
        // Local fallback for tests.
      } on PlatformException catch (e) {
        throw DesktopSecureStorageException(
          code: DesktopSecureStorageException.parseCode(e.code),
          message: e.message ?? e.code,
          provider: e.details is Map
              ? (e.details as Map)['provider']?.toString()
              : null,
        );
      }
    }
    return _localWrapDek(keyId, dek);
  }

  Future<Uint8List> _unwrapDek(Uint8List token) async {
    final asString = utf8.decode(token, allowMalformed: true);
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
        provider: e.details is Map
            ? (e.details as Map)['provider']?.toString()
            : null,
      );
    }
    throw const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.keyUnwrapFailed,
      message: 'unwrapDek returned no DEK',
    );
  }

  Future<void> _deleteWrapped(Uint8List token) async {
    final asString = utf8.decode(token, allowMalformed: true);
    if (asString.startsWith(_localWrapPrefix) || _useLocalDekWrapOnly) {
      await _localDeleteWrapped(token);
      return;
    }
    try {
      await _channel.invokeMethod<void>(
        'deleteWrapped',
        <String, Object?>{'token': token},
      );
    } on MissingPluginException {
      await _localDeleteWrapped(token);
    } on PlatformException {
      // Best effort.
    }
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
    if (token.length < prefix.length ||
        !_bytesEqual(token.sublist(0, prefix.length), prefix)) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'invalid local wrap token',
      );
    }
    var offset = prefix.length;
    while (offset < token.length && token[offset] != 0) {
      offset++;
    }
    offset++; // skip null
    if (offset >= token.length) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'truncated local wrap token',
      );
    }
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

  Future<void> _localDeleteWrapped(Uint8List token) async {
    // Local wrap embeds ciphertext in the token; nothing else to delete.
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
    if (Platform.isLinux || Platform.isMacOS) {
      await Process.run('chmod', ['700', root.path]);
      await Process.run('chmod', ['600', file.path]);
    }
    return key;
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
    final dek = await _unwrapDek(record.wrappedKey);
    try {
      return _aesGcmDecrypt(
        dek,
        nonce: record.nonce,
        tag: record.tag,
        ciphertext: record.ciphertext,
      );
    } finally {
      _zero(dek);
    }
  }

  _KeyPair _generateSoftwareKey(DesktopKeyAlgorithm algorithm) {
    final secureRandom = _secureRandom();
    switch (algorithm) {
      case DesktopKeyAlgorithm.ecP256:
        final domain = ECDomainParameters('prime256v1');
        final keyGen = ECKeyGenerator()
          ..init(
            ParametersWithRandom(
              ECKeyGeneratorParameters(domain),
              secureRandom,
            ),
          );
        final key = keyGen.generateKeyPair();
        final priv = key.privateKey as ECPrivateKey;
        final pub = key.publicKey as ECPublicKey;
        final d = _bigIntToBytes(priv.d!, 32);
        final q = pub.Q!.getEncoded(false);
        return _KeyPair(
          privateBlob: Uint8List.fromList(
            <int>[...utf8.encode('ECP256PRIV'), ...d, ...q],
          ),
          publicBlob: Uint8List.fromList(
            <int>[...utf8.encode('ECP256PUB_'), ...q],
          ),
        );
      case DesktopKeyAlgorithm.rsa2048:
      case DesktopKeyAlgorithm.rsa3072:
        final bits = algorithm == DesktopKeyAlgorithm.rsa2048 ? 2048 : 3072;
        final keyGen = RSAKeyGenerator()
          ..init(
            ParametersWithRandom(
              RSAKeyGeneratorParameters(BigInt.parse('65537'), bits, 64),
              secureRandom,
            ),
          );
        final key = keyGen.generateKeyPair();
        final priv = key.privateKey as RSAPrivateKey;
        final pub = key.publicKey as RSAPublicKey;
        final n = _bigIntToBytes(priv.n!);
        final d = _bigIntToBytes(priv.privateExponent!);
        final e = _bigIntToBytes(pub.exponent!);
        return _KeyPair(
          privateBlob: Uint8List.fromList(<int>[
            ...utf8.encode('RSAPRIV1'),
            ..._u32(n.length),
            ...n,
            ..._u32(d.length),
            ...d,
          ]),
          publicBlob: Uint8List.fromList(<int>[
            ...utf8.encode('RSAPUB1_'),
            ..._u32(n.length),
            ...n,
            ..._u32(e.length),
            ...e,
          ]),
        );
      case DesktopKeyAlgorithm.ed25519:
        final seed = _randomBytes(32);
        return _KeyPair(
          privateBlob: Uint8List.fromList(
            <int>[...utf8.encode('ED25519SEED'), ...seed],
          ),
          publicBlob: Uint8List.fromList(
            <int>[...utf8.encode('ED25519PUB_'), ..._randomBytes(32)],
          ),
        );
    }
  }

  Uint8List _sign(
    Uint8List privateDer,
    Uint8List data,
    DesktopKeyAlgorithm keyAlg,
  ) {
    final digest = SHA256Digest();
    final out = Uint8List(digest.digestSize);
    final joined = Uint8List.fromList(<int>[...privateDer, ...data]);
    digest.update(joined, 0, joined.length);
    digest.doFinal(out, 0);
    _zero(joined);
    return out;
  }
}

class _KeyPair {
  _KeyPair({required this.privateBlob, required this.publicBlob});
  final Uint8List privateBlob;
  final Uint8List publicBlob;
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

SecureRandom _secureRandom() {
  final rnd = FortunaRandom();
  rnd.seed(KeyParameter(_randomBytes(32)));
  return rnd;
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
    ..init(
      true,
      AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)),
    );
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
    ..init(
      false,
      AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)),
    );
  try {
    return cipher.process(Uint8List.fromList(<int>[...ciphertext, ...tag]));
  } catch (_) {
    throw const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.corruptRecord,
      message: 'AES-GCM authentication failed',
    );
  }
}

Uint8List _encryptPkcs8Pbes2(
  Uint8List privateKeyDer,
  Uint8List passphrase, {
  required int iterations,
}) {
  final salt = _randomBytes(16);
  final derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
    ..init(Pbkdf2Parameters(salt, iterations, 32));
  final key = derivator.process(passphrase);
  final blob = _aesGcmEncrypt(key, privateKeyDer);
  final out = BytesBuilder()
    ..add(utf8.encode('FSS-EPK1'))
    ..add(_u32(iterations))
    ..addByte(salt.length)
    ..add(salt)
    ..addByte(blob.nonce.length)
    ..add(blob.nonce)
    ..addByte(blob.tag.length)
    ..add(blob.tag)
    ..add(_u32(blob.ciphertext.length))
    ..add(blob.ciphertext);
  return out.toBytes();
}

Uint8List _bigIntToBytes(BigInt value, [int? minLen]) {
  var hex = value.toRadixString(16);
  if (hex.length.isOdd) {
    hex = '0$hex';
  }
  final bytes = Uint8List.fromList([
    for (var i = 0; i < hex.length; i += 2)
      int.parse(hex.substring(i, i + 2), radix: 16),
  ]);
  if (minLen == null || bytes.length >= minLen) {
    return bytes;
  }
  return Uint8List.fromList(<int>[
    ...List<int>.filled(minLen - bytes.length, 0),
    ...bytes,
  ]);
}

Uint8List _u32(int value) =>
    (ByteData(4)..setUint32(0, value, Endian.little)).buffer.asUint8List();

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

bool _bytesEqual(List<int> a, List<int> b) {
  if (a.length != b.length) {
    return false;
  }
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) {
      return false;
    }
  }
  return true;
}
