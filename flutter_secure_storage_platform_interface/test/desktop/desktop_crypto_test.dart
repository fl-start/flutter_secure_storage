import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('EC generate, PKCS#8 PBES2 round-trip, sign, PKCS#10 CSR', () {
    final material = DesktopCrypto.generate(DesktopKeyAlgorithm.ecP256);
    expect(material.privateKeyPkcs8Der.first, 0x30);
    expect(material.publicKeySpkiDer.first, 0x30);

    final passphrase = Uint8List.fromList(utf8.encode('test-pass-phrase'));
    final encrypted = DesktopCrypto.encryptPkcs8Pbes2(
      material.privateKeyPkcs8Der,
      passphrase,
      iterations: 1000,
    );
    final decrypted =
        DesktopCrypto.decryptEncryptedPrivateKey(encrypted, passphrase);
    expect(decrypted, material.privateKeyPkcs8Der);

    final pem = DesktopCrypto.toPem(encrypted, 'ENCRYPTED PRIVATE KEY');
    final fromPem =
        DesktopCrypto.decryptEncryptedPrivateKey(pem, passphrase);
    expect(fromPem, material.privateKeyPkcs8Der);

    final sig = DesktopCrypto.sign(
      material.privateKeyPkcs8Der,
      Uint8List.fromList(utf8.encode('hello')),
      keyAlgorithm: DesktopKeyAlgorithm.ecP256,
      signatureAlgorithm: SignatureAlgorithm.ecdsaSha256,
    );
    expect(sig.first, 0x30);

    final csr = DesktopCrypto.createPkcs10Csr(
      privateKeyPkcs8Der: material.privateKeyPkcs8Der,
      publicKeySpkiDer: material.publicKeySpkiDer,
      algorithm: DesktopKeyAlgorithm.ecP256,
      subjectDn: 'CN=device.test,O=Example',
    );
    expect(csr.first, 0x30);
    expect(utf8.decode(csr, allowMalformed: true), isNot(contains('FSS-CSR1')));
  });

  test('legacy EC blob converts to PKCS#8', () {
    final material = DesktopCrypto.generate(DesktopKeyAlgorithm.ecP256);
    final pkcs8 = DesktopCrypto.toPkcs8Der(
      material.legacyPrivateBlob,
      algorithm: DesktopKeyAlgorithm.ecP256,
    );
    expect(pkcs8.first, 0x30);
  });
}
