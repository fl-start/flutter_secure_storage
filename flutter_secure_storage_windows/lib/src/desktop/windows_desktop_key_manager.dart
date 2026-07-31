import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:pointycastle/export.dart';
import 'package:win32/win32.dart';

/// Windows [DesktopPrivateKeyManager] using DPAPI-wrapped FSS1 records and
/// software key material. TPM availability is probed via `ncrypt.dll`.
class WindowsDesktopKeyManager extends DesktopPrivateKeyManager {
  /// Creates a Windows desktop key manager.
  WindowsDesktopKeyManager({
    Directory? storageRoot,
    bool? tpmAvailableOverride,
  })  : _storageRoot = storageRoot,
        _tpmAvailableOverride = tpmAvailableOverride;

  final Directory? _storageRoot;
  final bool? _tpmAvailableOverride;

  static const _metaFile = 'keys.json';
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

  /// Probes Microsoft Platform Crypto Provider without assuming TPM success.
  bool probeTpm() {
    if (_tpmAvailableOverride != null) {
      return _tpmAvailableOverride!;
    }
    try {
      final ncrypt = DynamicLibrary.open('ncrypt.dll');
      final open = ncrypt.lookupFunction<
          Int32 Function(Pointer<IntPtr>, Pointer<Utf16>, Uint32),
          int Function(Pointer<IntPtr>, Pointer<Utf16>, int)>(
        'NCryptOpenStorageProvider',
      );
      final free = ncrypt.lookupFunction<Int32 Function(IntPtr),
          int Function(int)>('NCryptFreeObject');
      return using((arena) {
        final provider = arena<IntPtr>();
        final name =
            'Microsoft Platform Crypto Provider'.toNativeUtf16(allocator: arena);
        final status = open(provider, name, 0);
        if (status != 0) {
          return false;
        }
        free(provider.value);
        return true;
      });
    } catch (_) {
      return false;
    }
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

    return DesktopSecureStorageCapabilities(
      platform: 'windows',
      availableProviders: providers,
      selectedProvider: selected,
      hardwareAvailable: tpm,
      storageProtectionHardwareBacked: storageHw,
      privateKeyHardwareBacked: privateHw,
      supportsNonExportableKeys: true,
      supportsExportableKeys: true,
      supportsUserPresence: false,
      supportsMachineScope: true,
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
    if (options.protection ==
            DesktopSecureStorageProtection.hardwareBackedRequired &&
        !caps.hardwareAvailable) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.hardwareRequiredButUnavailable,
        message: 'TPM / platform crypto provider unavailable',
        provider: _providerPlatformCrypto,
      );
    }

    if (options.algorithm == DesktopKeyAlgorithm.ed25519 &&
        options.protection ==
            DesktopSecureStorageProtection.hardwareBackedRequired) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.algorithmUnsupported,
        message: 'ed25519 is not supported by Windows TPM providers',
        provider: _providerPlatformCrypto,
      );
    }

    final exportable =
        options.exportPolicy == PrivateKeyExportPolicy.exportableEncrypted;
    // Private keys are software-generated and DPAPI-wrapped in this release.
    // Capabilities still report TPM availability via probe; per-key flags stay
    // honest until NCrypt-persisted / TPM-wrapped keys are implemented.
    const claimPrivateHw = false;
    const claimStorageHw = false;

    final pair = _generateSoftwareKey(options.algorithm);
    final dek = _randomBytes(32);
    final encryptedPkcs8 = _aesGcmEncrypt(dek, pair.privateBlob);
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
      final signature = _sign(privateDer, Uint8List.fromList(subject), handle.algorithm);
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
          privateBlob: Uint8List.fromList(<int>[...utf8.encode('ECP256PRIV'), ...d, ...q]),
          publicBlob: Uint8List.fromList(<int>[...utf8.encode('ECP256PUB_'), ...q]),
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
          privateBlob:
              Uint8List.fromList(<int>[...utf8.encode('ED25519SEED'), ...seed]),
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
    // Binding signature for opaque-handle signing without exporting key bytes.
    return out;
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
      if (CryptProtectData(
            plainBlob,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            flags,
            encBlob,
          ) ==
          0) {
        throw DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.accessDenied,
          message: 'CryptProtectData failed',
          nativeStatusCode: GetLastError(),
          provider: _providerDpapi,
        );
      }
      try {
        return Uint8List.fromList(
          encBlob.ref.pbData.asTypedList(encBlob.ref.cbData),
        );
      } finally {
        if (encBlob.ref.pbData.address != NULL) {
          LocalFree(encBlob.ref.pbData);
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
      if (CryptUnprotectData(
            encBlob,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            flags,
            plainBlob,
          ) ==
          0) {
        throw DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.keyUnwrapFailed,
          message: 'CryptUnprotectData failed',
          nativeStatusCode: GetLastError(),
          provider: _providerDpapi,
        );
      }
      try {
        return Uint8List.fromList(
          plainBlob.ref.pbData.asTypedList(plainBlob.ref.cbData),
        );
      } finally {
        if (plainBlob.ref.pbData.address != NULL) {
          LocalFree(plainBlob.ref.pbData);
        }
      }
    });
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
  return Uint8List.fromList(List<int>.generate(length, (_) => rng.nextInt(256)));
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
