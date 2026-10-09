import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:flutter_secure_storage_windows/src/desktop/windows_der.dart';
import 'package:flutter_secure_storage_windows/src/desktop/windows_desktop_key_manager.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:scomm_openpgp/scomm_openpgp.dart';

import 'support/der_reader.dart';
import 'support/fake_tpm_key_backend.dart';

Matcher _throwsCode(DesktopSecureStorageErrorCode code) => throwsA(
      isA<DesktopSecureStorageException>().having((e) => e.code, 'code', code),
    );

DesktopPrivateKeyOptions _options(
  String keyId, {
  DesktopKeyAlgorithm algorithm = DesktopKeyAlgorithm.ecP256,
  DesktopSecureStorageProtection protection =
      DesktopSecureStorageProtection.hardwareBackedRequired,
  PrivateKeyExportPolicy exportPolicy = PrivateKeyExportPolicy.nonExportable,
  bool requireUserPresence = false,
}) =>
    DesktopPrivateKeyOptions(
      keyId: keyId,
      algorithm: algorithm,
      protection: protection,
      exportPolicy: exportPolicy,
      requireUserPresence: requireUserPresence,
    );

void main() {
  late Directory tmp;
  late FakeTpmKeyBackend tpm;
  late WindowsDesktopKeyManager manager;

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('fss_win_tpm_unit_');
    tpm = FakeTpmKeyBackend();
    manager = WindowsDesktopKeyManager(storageRoot: tmp, tpmBackend: tpm);
  });

  tearDown(() async {
    if (tmp.existsSync()) {
      await tmp.delete(recursive: true);
    }
  });

  Iterable<File> fss1Records() =>
      tmp.listSync().whereType<File>().where((f) => f.path.endsWith('.fss1'));

  group('hardwareBackedRequired', () {
    test('creates a TPM key with honest flags and no FSS1 record', () async {
      final handle = await manager.createPrivateKey(_options('app.tpm.ec'));
      expect(handle.hardwareBacked, isTrue);
      expect(handle.storageProtectionHardwareBacked, isTrue);
      expect(handle.provider, 'MS_PLATFORM_CRYPTO_PROVIDER');
      expect(handle.exportPolicy, PrivateKeyExportPolicy.nonExportable);
      expect(tpm.keys, hasLength(1));
      expect(tpm.keys.keys.single, startsWith('fss-dsk-'));
      expect(fss1Records(), isEmpty);

      final stored = await manager.getPrivateKeyHandle('app.tpm.ec');
      expect(stored?.hardwareBacked, isTrue);
    });

    test('fails closed without a TPM', () async {
      tpm.available = false;
      await expectLater(
        manager.createPrivateKey(_options('app.tpm.none')),
        _throwsCode(
          DesktopSecureStorageErrorCode.hardwareRequiredButUnavailable,
        ),
      );
    });

    test('rejects Ed25519, exportable keys, and user presence', () async {
      await expectLater(
        manager.createPrivateKey(
          _options('app.tpm.ed', algorithm: DesktopKeyAlgorithm.ed25519),
        ),
        _throwsCode(DesktopSecureStorageErrorCode.algorithmUnsupported),
      );
      await expectLater(
        manager.createPrivateKey(
          _options(
            'app.tpm.export',
            exportPolicy: PrivateKeyExportPolicy.exportableEncrypted,
          ),
        ),
        _throwsCode(DesktopSecureStorageErrorCode.invalidConfiguration),
      );
      await expectLater(
        manager.createPrivateKey(
          _options('app.tpm.presence', requireUserPresence: true),
        ),
        _throwsCode(DesktopSecureStorageErrorCode.invalidConfiguration),
      );
      expect(tpm.keys, isEmpty);
    });

    test('does not fall back when the TPM fails', () async {
      tpm.createError = const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.providerUnavailable,
        message: 'TPM busy',
      );
      await expectLater(
        manager.createPrivateKey(_options('app.tpm.fail')),
        _throwsCode(DesktopSecureStorageErrorCode.providerUnavailable),
      );
      expect(await manager.getPrivateKeyHandle('app.tpm.fail'), isNull);
    });

    test('capabilities exclude export and Ed25519', () async {
      final caps = await manager.getCapabilities(
        protection: DesktopSecureStorageProtection.hardwareBackedRequired,
      );
      expect(caps.privateKeyHardwareBacked, isTrue);
      expect(caps.supportsExportableKeys, isFalse);
      expect(caps.supportedAlgorithms,
          isNot(contains(DesktopKeyAlgorithm.ed25519)));
    });
  });

  group('hardwareBackedPreferred', () {
    test('uses the TPM when available', () async {
      final handle = await manager.createPrivateKey(
        _options(
          'app.pref.tpm',
          protection: DesktopSecureStorageProtection.hardwareBackedPreferred,
        ),
      );
      expect(handle.hardwareBacked, isTrue);
      expect(tpm.keys, hasLength(1));
    });

    test('falls back to software when the TPM fails', () async {
      tpm.createError = const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.algorithmUnsupported,
        message: 'RSA 3072 unsupported',
      );
      final handle = await manager.createPrivateKey(
        _options(
          'app.pref.fallback',
          algorithm: DesktopKeyAlgorithm.rsa3072,
          protection: DesktopSecureStorageProtection.hardwareBackedPreferred,
        ),
      );
      expect(handle.hardwareBacked, isFalse);
      expect(fss1Records(), hasLength(1));
    });

    test('keeps exportable and Ed25519 keys in software', () async {
      final exportable = await manager.createPrivateKey(
        _options(
          'app.pref.export',
          protection: DesktopSecureStorageProtection.hardwareBackedPreferred,
          exportPolicy: PrivateKeyExportPolicy.exportableEncrypted,
        ),
      );
      final ed = await manager.createPrivateKey(
        _options(
          'app.pref.ed',
          algorithm: DesktopKeyAlgorithm.ed25519,
          protection: DesktopSecureStorageProtection.hardwareBackedPreferred,
        ),
      );
      expect(exportable.hardwareBacked, isFalse);
      expect(ed.hardwareBacked, isFalse);
      expect(tpm.keys, isEmpty);
    });
  });

  test('TPM key signs, refuses export, and reads its public key live',
      () async {
    await manager.createPrivateKey(_options('app.tpm.sign'));
    final message = Uint8List.fromList('challenge'.codeUnits);
    final signature = await manager.sign(
      'app.tpm.sign',
      message,
      algorithm: SignatureAlgorithm.ecdsaSha256,
    );
    final spki = await manager.getPublicKey('app.tpm.sign');
    expect(
        nativeEcdsaVerify(NativeHash.sha256, spki, message, signature), isTrue);

    await expectLater(
      manager.exportPrivateKey(
        'app.tpm.sign',
        PrivateKeyExportOptions(
          encoding: PrivateKeyEncoding.pemPkcs8,
          passphrase: 'x',
        ),
      ),
      _throwsCode(DesktopSecureStorageErrorCode.keyNotExportable),
    );

    // Substituting another public key in keys.json does not change what the
    // TPM key reports.
    final metaFile = File('${tmp.path}${Platform.pathSeparator}keys.json');
    final meta =
        jsonDecode(metaFile.readAsStringSync()) as Map<String, dynamic>;
    final other = DesktopCryptoBackend.current
        .generateKeyPair(DesktopKeyAlgorithm.ecP256)
        .spkiDer;
    final entry = (meta['keys'] as Map<String, dynamic>)['app.tpm.sign']
        as Map<String, dynamic>;
    entry['publicKeySpki'] = base64Encode(other);
    metaFile.writeAsStringSync(jsonEncode(meta));
    expect(await manager.getPublicKey('app.tpm.sign'), spki);
  });

  test('TPM CSR carries the TPM public key and its signature', () async {
    await manager.createPrivateKey(_options('app.tpm.csr'));
    final csr = await manager.createCertificateSigningRequest(
      'app.tpm.csr',
      const CertificateSigningRequestOptions(
        subjectDistinguishedName: 'CN=license-device,O=Scomm',
      ),
    );
    final parts = DerReader.children(csr);
    final requestInfo = parts[0];
    final spki = await manager.getPublicKey('app.tpm.csr');
    expect(DerReader.children(requestInfo)[2], spki);
    expect(
      nativeEcdsaVerify(
        NativeHash.sha256,
        spki,
        requestInfo,
        DerReader.bitStringContent(parts[2]),
      ),
      isTrue,
    );
  });

  test('delete removes the TPM key, and keeps the record if that fails',
      () async {
    await manager.createPrivateKey(_options('app.tpm.del'));
    tpm.deleteError = const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.accessDenied,
      message: 'denied',
    );
    await expectLater(
      manager.deletePrivateKey('app.tpm.del'),
      _throwsCode(DesktopSecureStorageErrorCode.accessDenied),
    );
    expect(await manager.getPrivateKeyHandle('app.tpm.del'), isNotNull);

    tpm.deleteError = null;
    await manager.deletePrivateKey('app.tpm.del');
    expect(await manager.getPrivateKeyHandle('app.tpm.del'), isNull);
    expect(tpm.keys, isEmpty);
    expect(tpm.deleted, hasLength(1));
  });

  group('WindowsDer', () {
    test('EC SPKI matches OpenSSL for the same point', () {
      final spki = DesktopCryptoBackend.current
          .generateKeyPair(DesktopKeyAlgorithm.ecP256)
          .spkiDer;
      final point = DerReader.bitStringContent(DerReader.children(spki)[1]);
      expect(point[0], 0x04);
      expect(
        WindowsDer.ecP256Spki(
          Uint8List.sublistView(point, 1, 33),
          Uint8List.sublistView(point, 33, 65),
        ),
        spki,
      );
    });

    test('RSA SPKI matches OpenSSL for the same key', () {
      final spki = DesktopCryptoBackend.current
          .generateKeyPair(DesktopKeyAlgorithm.rsa2048)
          .spkiDer;
      final rsaKey = DerReader.bitStringContent(DerReader.children(spki)[1]);
      final fields = DerReader.children(rsaKey);
      expect(
        WindowsDer.rsaSpki(
          DerReader.content(fields[0]),
          DerReader.content(fields[1]),
        ),
        spki,
      );
    });

    test('raw ECDSA signature re-encodes as DER OpenSSL verifies', () {
      final pair = DesktopCryptoBackend.current
          .generateKeyPair(DesktopKeyAlgorithm.ecP256);
      final message = Uint8List.fromList('raw'.codeUnits);
      final der = DesktopCryptoBackend.current
          .sign(pair.pkcs8Der, message, algorithm: DesktopKeyAlgorithm.ecP256);
      final fields = DerReader.children(der);
      Uint8List fixed(Uint8List v) {
        final out = Uint8List(32);
        final trimmed = v.length > 32 ? v.sublist(v.length - 32) : v;
        out.setRange(32 - trimmed.length, 32, trimmed);
        return out;
      }

      final raw = Uint8List.fromList([
        ...fixed(DerReader.content(fields[0])),
        ...fixed(DerReader.content(fields[1])),
      ]);
      final reencoded = WindowsDer.ecdsaRawToDer(raw);
      expect(reencoded, der);
      expect(
        nativeEcdsaVerify(NativeHash.sha256, pair.spkiDer, message, reencoded),
        isTrue,
      );
    });

    test('subject name encodes like the OpenSSL CSR path', () {
      final pair = DesktopCryptoBackend.current
          .generateKeyPair(DesktopKeyAlgorithm.ecP256);
      const dn = 'CN=license-device,O=Scomm,OU=Billing';
      final openssl = DesktopCryptoBackend.current.createCsr(pair.pkcs8Der, dn);
      final opensslName = DerReader.children(DerReader.children(openssl)[0])[1];
      expect(WindowsDer.distinguishedName(dn), opensslName);
    });

    test('unknown attribute types are rejected', () {
      expect(
        () => WindowsDer.distinguishedName('XX=nope'),
        _throwsCode(DesktopSecureStorageErrorCode.invalidConfiguration),
      );
    });
  });
}
