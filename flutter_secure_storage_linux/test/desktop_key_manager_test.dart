import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage_linux/src/desktop/linux_desktop_key_manager.dart';
import 'package:flutter_secure_storage_linux/src/desktop/linux_tpm2_backend.dart';
import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

class _TestTpm extends LinuxTpm2Backend {
  _TestTpm(this.root) : super(storageRoot: root, availableOverride: true);
  final Directory root;
  final Map<String, Uint8List> pubs = {};

  @override
  Future<LinuxTpmKey> createEccP256(String keyId) async {
    final material = DesktopCrypto.generate(DesktopKeyAlgorithm.ecP256);
    pubs[keyId] = material.publicKeySpkiDer;
    final dir = Directory('${root.path}/tpm/${sanitizeKeyIdForFilename(keyId)}')
      ..createSync(recursive: true);
    return LinuxTpmKey(
      keyId: keyId,
      directory: dir.path,
      publicKeySpkiDer: material.publicKeySpkiDer,
    );
  }

  @override
  Future<Uint8List> sign(String keyId, Uint8List data) async =>
      Uint8List.fromList(<int>[1, 2, 3, 4, ...data]);

  @override
  Future<void> delete(String keyId) async {
    pubs.remove(keyId);
  }
}

void main() {
  late Directory tmp;
  late LinuxDesktopKeyManager manager;

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('fss_linux_keys_');
    manager = LinuxDesktopKeyManager(
      storageRoot: tmp,
      tpmAvailableOverride: false,
      secretServiceAvailableOverride: false,
      systemdCredsAvailableOverride: false,
      useLocalDekWrapOnly: true,
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

  test('TPM path create/sign/delete when backend available', () async {
    final tpm = _TestTpm(tmp);
    final tpmManager = LinuxDesktopKeyManager(
      storageRoot: tmp,
      tpmAvailableOverride: true,
      secretServiceAvailableOverride: false,
      systemdCredsAvailableOverride: false,
      useLocalDekWrapOnly: true,
      tpmBackend: tpm,
    );
    final handle = await tpmManager.createPrivateKey(
      DesktopPrivateKeyOptions(
        keyId: 'app.tpm.key',
        algorithm: DesktopKeyAlgorithm.ecP256,
        protection: DesktopSecureStorageProtection.hardwareBackedRequired,
      ),
    );
    expect(handle.hardwareBacked, isTrue);
    expect(handle.provider, 'tpm2');
    final sig = await tpmManager.sign(
      'app.tpm.key',
      Uint8List.fromList([9, 9]),
      algorithm: SignatureAlgorithm.ecdsaSha256,
    );
    expect(sig.length, greaterThan(4));
    await tpmManager.deletePrivateKey('app.tpm.key');
    expect(await tpmManager.getPrivateKeyHandle('app.tpm.key'), isNull);
  });

  test('PKCS#8 export/import round-trip and PKCS#10 CSR', () async {
    await manager.createPrivateKey(
      DesktopPrivateKeyOptions(
        keyId: 'app.device.identity',
        algorithm: DesktopKeyAlgorithm.ecP256,
        protection: DesktopSecureStorageProtection.softwareProtected,
        exportPolicy: PrivateKeyExportPolicy.exportableEncrypted,
      ),
    );
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

    await manager.deletePrivateKey('app.device.identity');
    final imported = await manager.importPrivateKey(
      exported.bytes,
      PrivateKeyImportOptions(
        keyId: 'app.device.identity',
        protection: DesktopSecureStorageProtection.softwareProtected,
        exportPolicy: PrivateKeyExportPolicy.exportableEncrypted,
        passphrase: 'test-passphrase-not-logged',
      ),
    );
    expect(imported.handle.keyId, 'app.device.identity');

    final csr = await manager.createCertificateSigningRequest(
      'app.device.identity',
      CertificateSigningRequestOptions(
        subjectDistinguishedName: 'CN=test',
      ),
    );
    expect(csr.first, 0x30);
    expect(utf8Contains(csr, 'FSS-CSR1'), isFalse);

    final sig = await manager.sign(
      'app.device.identity',
      Uint8List.fromList(utf8.encode('hello')),
      algorithm: SignatureAlgorithm.ecdsaSha256,
    );
    expect(sig.first, 0x30);
  });

  test('non-exportable refuses export', () async {
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

  test('capabilities list systemd/tpm when available', () async {
    final capsManager = LinuxDesktopKeyManager(
      storageRoot: tmp,
      tpmAvailableOverride: true,
      secretServiceAvailableOverride: false,
      systemdCredsAvailableOverride: true,
      useLocalDekWrapOnly: true,
      tpmBackend: _TestTpm(tmp),
    );
    final caps = await capsManager.getCapabilities(
      protection: DesktopSecureStorageProtection.hardwareBackedPreferred,
    );
    expect(caps.availableProviders, contains('tpm2'));
    expect(caps.availableProviders, contains('systemd_creds'));
    expect(caps.selectedProvider, 'tpm2');
  });
}

bool utf8Contains(Uint8List bytes, String needle) =>
    String.fromCharCodes(bytes).contains(needle);
