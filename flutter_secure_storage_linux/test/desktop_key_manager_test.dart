import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage_linux/src/desktop/linux_desktop_key_manager.dart';
import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Directory tmp;
  late LinuxDesktopKeyManager manager;

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('fss_linux_keys_');
    manager = LinuxDesktopKeyManager(
      storageRoot: tmp,
      tpmAvailableOverride: false,
      secretServiceAvailableOverride: false,
      useLocalDekWrapOnly: true,
    );
  });

  tearDown(() async {
    if (tmp.existsSync()) {
      await tmp.delete(recursive: true);
    }
  });

  test('hardware required fails closed', () async {
    expect(
      () => manager.createPrivateKey(
        DesktopPrivateKeyOptions(
          keyId: 'app.test.hw',
          algorithm: DesktopKeyAlgorithm.ecP256,
          protection: DesktopSecureStorageProtection.hardwareBackedRequired,
        ),
      ),
      throwsA(
        isA<DesktopSecureStorageException>().having(
          (e) => e.code,
          'code',
          DesktopSecureStorageErrorCode.hardwareRequiredButUnavailable,
        ),
      ),
    );
  });

  test('hardware preferred reports fallback without claiming private HW',
      () async {
    final caps = await manager.getCapabilities(
      protection: DesktopSecureStorageProtection.hardwareBackedPreferred,
    );
    expect(caps.hardwareAvailable, isFalse);
    expect(caps.fallbackReason, isNotNull);
    expect(caps.privateKeyHardwareBacked, isFalse);
    expect(caps.selectedProvider, 'protected_file');
  });

  test('platformDefault without secret service uses protected_file', () async {
    final caps = await manager.getCapabilities();
    expect(caps.selectedProvider, 'protected_file');
    expect(caps.supportsExportableKeys, isTrue);
    expect(caps.supportsCsrGeneration, isTrue);
    expect(caps.availableProviders, contains('protected_file'));
    expect(caps.availableProviders, isNot(contains('secret_service')));
  });

  test('exportable key exports encrypted and non-exportable refuses', () async {
    final exportable = await manager.createPrivateKey(
      DesktopPrivateKeyOptions(
        keyId: 'app.device.identity',
        algorithm: DesktopKeyAlgorithm.ecP256,
        protection: DesktopSecureStorageProtection.softwareProtected,
        exportPolicy: PrivateKeyExportPolicy.exportableEncrypted,
      ),
    );
    expect(exportable.hardwareBacked, isFalse);
    expect(exportable.exportPolicy, PrivateKeyExportPolicy.exportableEncrypted);

    final exported = await manager.exportPrivateKey(
      'app.device.identity',
      PrivateKeyExportOptions(
        encoding: PrivateKeyEncoding.pemPkcs8,
        passphrase: 'test-passphrase-not-logged',
        pbkdf2Iterations: 1000,
      ),
    );
    expect(utf8Contains(exported.bytes, 'ENCRYPTED PRIVATE KEY'), isTrue);

    await manager.createPrivateKey(
      DesktopPrivateKeyOptions(
        keyId: 'app.admin.identity',
        algorithm: DesktopKeyAlgorithm.ecP256,
        protection: DesktopSecureStorageProtection.softwareProtected,
      ),
    );
    expect(
      () => manager.exportPrivateKey(
        'app.admin.identity',
        PrivateKeyExportOptions(
          encoding: PrivateKeyEncoding.pemPkcs8,
          passphrase: 'x',
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
  });

  test('sign and CSR work without export', () async {
    await manager.createPrivateKey(
      DesktopPrivateKeyOptions(
        keyId: 'app.sign.key',
        algorithm: DesktopKeyAlgorithm.ecP256,
        protection: DesktopSecureStorageProtection.softwareProtected,
      ),
    );
    final sig = await manager.sign(
      'app.sign.key',
      Uint8List.fromList('hello'.codeUnits),
      algorithm: SignatureAlgorithm.ecdsaSha256,
    );
    expect(sig.length, greaterThan(0));

    final csr = await manager.createCertificateSigningRequest(
      'app.sign.key',
      CertificateSigningRequestOptions(
        subjectDistinguishedName: 'CN=test',
      ),
    );
    expect(utf8Contains(csr, 'FSS-CSR1'), isTrue);
  });

  test('delete removes key', () async {
    await manager.createPrivateKey(
      DesktopPrivateKeyOptions(
        keyId: 'app.delete.me',
        algorithm: DesktopKeyAlgorithm.ecP256,
        protection: DesktopSecureStorageProtection.softwareProtected,
      ),
    );
    await manager.deletePrivateKey('app.delete.me');
    expect(await manager.getPrivateKeyHandle('app.delete.me'), isNull);
  });

  test('mocked TPM capability probe does not claim private key HW', () async {
    final tpmManager = LinuxDesktopKeyManager(
      storageRoot: tmp,
      tpmAvailableOverride: true,
      secretServiceAvailableOverride: false,
      useLocalDekWrapOnly: true,
    );
    final caps = await tpmManager.getCapabilities(
      protection: DesktopSecureStorageProtection.hardwareBackedRequired,
    );
    expect(caps.hardwareAvailable, isTrue);
    expect(caps.privateKeyHardwareBacked, isFalse);
    expect(caps.selectedProvider, 'tpm2_optional');
  });
}

bool utf8Contains(Uint8List bytes, String needle) =>
    String.fromCharCodes(bytes).contains(needle);
