import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('accepts namespaced key ids', () {
    expect(normalizeAndValidateKeyId('idr.admin.identity'), 'idr.admin.identity');
  });

  test('rejects path traversal', () {
    expect(
      () => normalizeAndValidateKeyId('../etc/passwd'),
      throwsA(
        isA<DesktopSecureStorageException>().having(
          (e) => e.code,
          'code',
          DesktopSecureStorageErrorCode.invalidConfiguration,
        ),
      ),
    );
  });

  test('rejects empty key id', () {
    expect(
      () => normalizeAndValidateKeyId('   '),
      throwsA(isA<DesktopSecureStorageException>()),
    );
  });

  test('sanitize replaces unsafe filename chars', () {
    expect(sanitizeKeyIdForFilename('a/b@c'), 'a_b_c');
    expect(sanitizeKeyIdForFilename('abc.def'), 'abc.def');
  });

  test('export options require passphrase', () {
    expect(
      () => PrivateKeyExportOptions(encoding: PrivateKeyEncoding.pemPkcs8),
      throwsA(
        isA<DesktopSecureStorageException>().having(
          (e) => e.code,
          'code',
          DesktopSecureStorageErrorCode.invalidExportPassphrase,
        ),
      ),
    );
  });

  test('capabilities round-trip through map', () {
    const caps = DesktopSecureStorageCapabilities(
      platform: 'windows',
      availableProviders: ['dpapi', 'platform_crypto'],
      selectedProvider: 'dpapi',
      hardwareAvailable: true,
      storageProtectionHardwareBacked: false,
      privateKeyHardwareBacked: false,
      supportsNonExportableKeys: true,
      supportsExportableKeys: true,
      supportsUserPresence: false,
      supportsMachineScope: true,
      supportsCsrGeneration: true,
      supportedAlgorithms: [DesktopKeyAlgorithm.ecP256],
      supportedExportFormats: [PrivateKeyEncoding.pemPkcs8],
      fallbackReason: 'tpm unavailable',
    );
    final again = DesktopSecureStorageCapabilities.fromMap(caps.toMap());
    expect(again.platform, 'windows');
    expect(again.fallbackReason, 'tpm unavailable');
    expect(again.supportedAlgorithms, contains(DesktopKeyAlgorithm.ecP256));
  });
}
