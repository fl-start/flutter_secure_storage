import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

/// Proves iOS option serialization remains unchanged by the desktop work.
void main() {
  test('IOSOptions.defaultOptions map is stable', () {
    final map = IOSOptions.defaultOptions.toMap();
    // Desktop-only keys must never appear on iOS options.
    expect(map.containsKey('protection'), isFalse);
    expect(map.containsKey('exportPolicy'), isFalse);
    expect(map.containsKey('machineScoped'), isFalse);
    expect(map.containsKey('usesDataProtectionKeychain'), isFalse);
  });

  test('IOSOptions with secure enclave serializes expected keys only', () {
    const options = IOSOptions(
      accountName: 'test.service',
      useSecureEnclave: true,
      synchronizable: false,
      accessibility: KeychainAccessibility.first_unlock_this_device,
    );
    final map = options.toMap();
    expect(map['accountName'], 'test.service');
    expect(map['useSecureEnclave'], 'true');
    expect(map['synchronizable'], 'false');
    expect(map['accessibility'], isNotNull);
    expect(map.keys, isNot(contains('usesDataProtectionKeychain')));
  });

  test('MacOsOptions keeps data protection keychain default without changing iOS', () {
    final ios = IOSOptions.defaultOptions.toMap();
    final mac = MacOsOptions.defaultOptions.toMap();
    expect(mac['usesDataProtectionKeychain'], 'true');
    expect(ios.containsKey('usesDataProtectionKeychain'), isFalse);
  });
}
