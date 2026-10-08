import 'dart:typed_data';

import 'desktop_enums.dart';
import 'desktop_errors.dart';

/// A private key as PKCS#8 PrivateKeyInfo DER plus its SubjectPublicKeyInfo DER.
typedef DesktopKeyPairDer = ({Uint8List pkcs8Der, Uint8List spkiDer});

/// The crypto the desktop key managers need, supplied by the host app.
///
/// This package ships no crypto implementation. The host installs one backed
/// by a single library (the Scomm app uses OpenSSL) with
/// [DesktopCryptoBackend.install] before any desktop key operation.
abstract interface class DesktopCryptoBackend {
  Uint8List randomBytes(int length);

  /// New key pair for [algorithm].
  DesktopKeyPairDer generateKeyPair(DesktopKeyAlgorithm algorithm);

  /// EC P-256 key pair from a 32-byte private scalar.
  DesktopKeyPairDer ecP256FromScalar(Uint8List scalar);

  /// SubjectPublicKeyInfo DER of a PKCS#8 private key.
  Uint8List publicSpkiFromPkcs8(Uint8List pkcs8Der);

  /// ECDSA-SHA256 (ASN.1 DER), RSASSA-PKCS1-v1_5-SHA256, or Ed25519, by the
  /// key's [algorithm].
  Uint8List sign(
    Uint8List pkcs8Der,
    Uint8List data, {
    required DesktopKeyAlgorithm algorithm,
  });

  /// PBES2 EncryptedPrivateKeyInfo (PBKDF2-HMAC-SHA256, AES-256-CBC).
  Uint8List encryptPkcs8(
    Uint8List pkcs8Der,
    Uint8List passphrase, {
    required int iterations,
  });

  /// Throws on a wrong passphrase or an unreadable key.
  Uint8List decryptPkcs8(Uint8List encryptedDer, Uint8List passphrase);

  /// PKCS#10 CertificationRequest for the key, signed by it.
  Uint8List createCsr(Uint8List pkcs8Der, String subjectDn);

  ({Uint8List ciphertext, Uint8List tag}) aes256GcmEncrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
  });

  /// Throws when authentication fails.
  Uint8List aes256GcmDecrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List ciphertext,
    required Uint8List tag,
  });

  Uint8List pbkdf2HmacSha256(
    Uint8List passphrase,
    Uint8List salt,
    int iterations,
    int length,
  );

  static DesktopCryptoBackend? _installed;

  static void install(DesktopCryptoBackend backend) {
    _installed = backend;
  }

  static DesktopCryptoBackend get current =>
      _installed ??
      (throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.invalidConfiguration,
        message: 'DesktopCryptoBackend.install must run before desktop key '
            'operations',
      ));
}
