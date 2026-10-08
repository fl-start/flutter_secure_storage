import 'dart:typed_data';

import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:scomm_openpgp/scomm_openpgp.dart';

/// OpenSSL-backed [DesktopCryptoBackend] for tests, through scomm_openpgp.
/// Set `SCOMM_OPENPGP_LIB` to a built `scomm_openpgp` library.
final class NativeDesktopBackend implements DesktopCryptoBackend {
  const NativeDesktopBackend();

  static void install() =>
      DesktopCryptoBackend.install(const NativeDesktopBackend());

  @override
  Uint8List randomBytes(int length) => nativeRandom(length);

  @override
  DesktopKeyPairDer generateKeyPair(DesktopKeyAlgorithm algorithm) {
    final kind = switch (algorithm) {
      DesktopKeyAlgorithm.ecP256 => NativeKeyKind.ecP256,
      DesktopKeyAlgorithm.rsa2048 => NativeKeyKind.rsa2048,
      DesktopKeyAlgorithm.rsa3072 => NativeKeyKind.rsa3072,
      DesktopKeyAlgorithm.ed25519 => NativeKeyKind.ed25519,
    };
    return nativePkeyGenerate(kind);
  }

  @override
  DesktopKeyPairDer ecP256FromScalar(Uint8List scalar) =>
      nativeEcP256FromScalar(scalar);

  @override
  Uint8List publicSpkiFromPkcs8(Uint8List pkcs8Der) =>
      nativePkcs8PublicSpki(pkcs8Der);

  @override
  Uint8List sign(
    Uint8List pkcs8Der,
    Uint8List data, {
    required DesktopKeyAlgorithm algorithm,
  }) {
    final scheme = switch (algorithm) {
      DesktopKeyAlgorithm.ecP256 => NativeSignScheme.ecdsaSha256,
      DesktopKeyAlgorithm.rsa2048 ||
      DesktopKeyAlgorithm.rsa3072 =>
        NativeSignScheme.rsaPkcs1Sha256,
      DesktopKeyAlgorithm.ed25519 => NativeSignScheme.ed25519,
    };
    return nativePkeySign(scheme, pkcs8Der, data);
  }

  @override
  Uint8List encryptPkcs8(
    Uint8List pkcs8Der,
    Uint8List passphrase, {
    required int iterations,
  }) =>
      nativePkcs8Encrypt(pkcs8Der, passphrase, iterations: iterations);

  @override
  Uint8List decryptPkcs8(Uint8List encryptedDer, Uint8List passphrase) =>
      nativePkcs8Decrypt(encryptedDer, passphrase);

  @override
  Uint8List createCsr(Uint8List pkcs8Der, String subjectDn) =>
      nativeCsrCreate(pkcs8Der, subjectDn);

  @override
  ({Uint8List ciphertext, Uint8List tag}) aes256GcmEncrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
  }) =>
      nativeAes256GcmEncrypt(key: key, nonce: nonce, plaintext: plaintext);

  @override
  Uint8List aes256GcmDecrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List tag,
  }) =>
      nativeAes256GcmDecrypt(
        key: key,
        nonce: nonce,
        ciphertext: ciphertext,
        tag: tag,
      );

  @override
  Uint8List pbkdf2HmacSha256(
    Uint8List passphrase,
    Uint8List salt,
    int iterations,
    int length,
  ) =>
      nativePbkdf2(
        NativeHash.sha256,
        password: passphrase,
        salt: salt,
        iterations: iterations,
        length: length,
      );
}
