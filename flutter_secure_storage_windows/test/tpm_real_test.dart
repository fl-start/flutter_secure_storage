// Exercises the real TPM through the Microsoft Platform Crypto Provider.
//
// Opt-in because it creates and deletes keys in the machine's TPM:
//   FSS_TEST_REAL_TPM=1 flutter test test/tpm_real_test.dart
@TestOn('windows')
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:flutter_secure_storage_windows/src/desktop/windows_desktop_key_manager.dart';
import 'package:flutter_secure_storage_windows/src/desktop/windows_tpm_key_backend.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:scomm_openpgp/scomm_openpgp.dart';

import 'support/der_reader.dart';

void main() {
  final enabled = Platform.environment['FSS_TEST_REAL_TPM'] == '1';
  final skip = enabled ? false : 'set FSS_TEST_REAL_TPM=1 to run';

  late Directory tmp;
  late WindowsDesktopKeyManager manager;

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('fss_win_tpm_');
    manager = WindowsDesktopKeyManager(storageRoot: tmp);
  });

  tearDown(() async {
    // Try every key so one failure does not leave the rest in the TPM.
    Object? failure;
    for (final handle in await manager.listPrivateKeys()) {
      try {
        await manager.deletePrivateKey(handle.keyId);
      } on Object catch (e) {
        failure ??= e;
      }
    }
    if (tmp.existsSync()) {
      await tmp.delete(recursive: true);
    }
    if (failure != null) {
      Error.throwWithStackTrace(failure, StackTrace.current);
    }
  });

  test('probe finds a TPM 2.0', () {
    expect(NcryptTpmKeyBackend().probe(), isTrue);
  }, skip: skip);

  test('EC P-256 key lives in the TPM and signs verifiably', () async {
    final handle = await manager.createPrivateKey(
      DesktopPrivateKeyOptions(
        keyId: 'fss.test.tpm.ec',
        algorithm: DesktopKeyAlgorithm.ecP256,
        protection: DesktopSecureStorageProtection.hardwareBackedRequired,
      ),
    );
    expect(handle.hardwareBacked, isTrue);
    expect(handle.exportPolicy, PrivateKeyExportPolicy.nonExportable);
    expect(
      tmp.listSync().whereType<File>().where((f) => f.path.endsWith('.fss1')),
      isEmpty,
    );

    final spki = await manager.getPublicKey('fss.test.tpm.ec');
    final message = Uint8List.fromList('device challenge'.codeUnits);
    final signature = await manager.sign(
      'fss.test.tpm.ec',
      message,
      algorithm: SignatureAlgorithm.ecdsaSha256,
    );
    expect(
        nativeEcdsaVerify(NativeHash.sha256, spki, message, signature), isTrue);
    expect(
      nativeEcdsaVerify(
        NativeHash.sha256,
        spki,
        Uint8List.fromList('other'.codeUnits),
        signature,
      ),
      isFalse,
    );

    await expectLater(
      manager.exportPrivateKey(
        'fss.test.tpm.ec',
        PrivateKeyExportOptions(
          encoding: PrivateKeyEncoding.pemPkcs8,
          passphrase: 'not-used',
        ),
      ),
      throwsA(
        isA<DesktopSecureStorageException>().having(
          (e) => e.code,
          'code',
          DesktopSecureStorageErrorCode.keyNotExportable,
        ),
      ),
    );
  }, skip: skip);

  test('TPM CSR is signed by the TPM key', () async {
    await manager.createPrivateKey(
      DesktopPrivateKeyOptions(
        keyId: 'fss.test.tpm.csr',
        algorithm: DesktopKeyAlgorithm.ecP256,
        protection: DesktopSecureStorageProtection.hardwareBackedRequired,
      ),
    );
    final csr = await manager.createCertificateSigningRequest(
      'fss.test.tpm.csr',
      const CertificateSigningRequestOptions(
        subjectDistinguishedName: 'CN=license-device,O=Scomm',
      ),
    );
    final parts = DerReader.children(csr);
    expect(parts, hasLength(3));
    final requestInfo = parts[0];
    final signature = DerReader.bitStringContent(parts[2]);
    final spki = await manager.getPublicKey('fss.test.tpm.csr');
    expect(DerReader.children(requestInfo)[2], spki);
    expect(
      nativeEcdsaVerify(NativeHash.sha256, spki, requestInfo, signature),
      isTrue,
    );
  }, skip: skip);

  test('RSA 2048 TPM key signs PKCS#1 v1.5', () async {
    await manager.createPrivateKey(
      DesktopPrivateKeyOptions(
        keyId: 'fss.test.tpm.rsa',
        algorithm: DesktopKeyAlgorithm.rsa2048,
        protection: DesktopSecureStorageProtection.hardwareBackedRequired,
      ),
    );
    final spki = await manager.getPublicKey('fss.test.tpm.rsa');
    final message = Uint8List.fromList('rsa challenge'.codeUnits);
    final signature = await manager.sign(
      'fss.test.tpm.rsa',
      message,
      algorithm: SignatureAlgorithm.rsaPkcs1Sha256,
    );
    expect(signature, hasLength(256));
    expect(
      nativeRsaPkcs1Verify(NativeHash.sha256, spki, message, signature),
      isTrue,
    );
    final pss = await manager.sign(
      'fss.test.tpm.rsa',
      message,
      algorithm: SignatureAlgorithm.rsaPssSha256,
    );
    expect(pss, hasLength(256));
  }, skip: skip);

  test('delete removes the key from the TPM', () async {
    await manager.createPrivateKey(
      DesktopPrivateKeyOptions(
        keyId: 'fss.test.tpm.delete',
        algorithm: DesktopKeyAlgorithm.ecP256,
        protection: DesktopSecureStorageProtection.hardwareBackedRequired,
      ),
    );
    await manager.deletePrivateKey('fss.test.tpm.delete');
    expect(await manager.getPrivateKeyHandle('fss.test.tpm.delete'), isNull);
    // Deleting a key that is already gone from the TPM is not an error.
    NcryptTpmKeyBackend().deleteKey(
      keyName: 'fss-dsk-does-not-exist',
      machineScoped: false,
    );
  }, skip: skip);
}
