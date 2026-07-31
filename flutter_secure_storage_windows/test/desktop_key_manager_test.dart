import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:flutter_secure_storage_windows/src/desktop/windows_desktop_key_manager.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Directory tmp;
  late WindowsDesktopKeyManager manager;

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('fss_win_keys_');
    manager = WindowsDesktopKeyManager(
      storageRoot: tmp,
      tpmAvailableOverride: false,
    );
  });

  tearDown(() async {
    if (tmp.existsSync()) {
      await tmp.delete(recursive: true);
    }
  });

  test('hardware required fails when TPM unavailable', () async {
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

  test('hardware preferred reports fallback', () async {
    final caps = await manager.getCapabilities(
      protection: DesktopSecureStorageProtection.hardwareBackedPreferred,
    );
    expect(caps.hardwareAvailable, isFalse);
    expect(caps.fallbackReason, isNotNull);
    expect(caps.privateKeyHardwareBacked, isFalse);
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
    expect(utf8Contains(exported.bytes, 'FSS-EPK1'), isFalse);

    final locked = await manager.createPrivateKey(
      DesktopPrivateKeyOptions(
        keyId: 'app.admin.identity',
        algorithm: DesktopKeyAlgorithm.ecP256,
        protection: DesktopSecureStorageProtection.softwareProtected,
      ),
    );
    expect(locked.exportPolicy, PrivateKeyExportPolicy.nonExportable);
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

  test('sign works without export', () async {
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

  test('mocked TPM capabilities', () async {
    final tpmManager = WindowsDesktopKeyManager(
      storageRoot: tmp,
      tpmAvailableOverride: true,
    );
    final caps = await tpmManager.getCapabilities(
      protection: DesktopSecureStorageProtection.hardwareBackedRequired,
    );
    expect(caps.hardwareAvailable, isTrue);
    expect(caps.selectedProvider, contains('PLATFORM_CRYPTO'));
  });
}

bool utf8Contains(Uint8List bytes, String needle) =>
    String.fromCharCodes(bytes).contains(needle);
