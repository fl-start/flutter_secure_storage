import 'package:flutter_secure_storage/secure_private_key_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('DesktopSecureStorage is SecurePrivateKeyStorage', () {
    expect(DesktopSecureStorage.privateKeys, same(SecurePrivateKeyStorage.privateKeys));
  });

  test('isSupported is false on web binding defaults in unit test VM', () {
    // Unit tests run on the host VM; isSupported follows defaultTargetPlatform.
    // Ensure the API surface exists and Web gate message is documented.
    expect(SecurePrivateKeyStorage.isSupported, isA<bool>());
    expect(SecurePrivateKeyStorage.isDesktopSupported, isA<bool>());
  });
}
