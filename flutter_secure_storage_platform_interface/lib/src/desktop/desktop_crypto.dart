import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'desktop_crypto_backend.dart';
import 'desktop_enums.dart';
import 'desktop_errors.dart';

/// Shared desktop crypto: PKCS#8 / PKCS#10 / signatures + legacy FSS blobs.
///
/// The primitives come from the installed [DesktopCryptoBackend].
abstract final class DesktopCrypto {
  static const _fssEpk1 = 'FSS-EPK1';
  static const _ecPrivMagic = 'ECP256PRIV';

  static DesktopCryptoBackend get _backend => DesktopCryptoBackend.current;

  static Uint8List randomBytes(int length) => _backend.randomBytes(length);

  /// Generate software key material as PKCS#8 PrivateKeyInfo DER + SPKI DER.
  static DesktopKeyMaterial generate(DesktopKeyAlgorithm algorithm) {
    final pair = _backend.generateKeyPair(algorithm);
    return DesktopKeyMaterial(
      algorithm: algorithm,
      privateKeyPkcs8Der: pair.pkcs8Der,
      publicKeySpkiDer: pair.spkiDer,
    );
  }

  /// SubjectPublicKeyInfo DER of a PKCS#8 private key.
  static Uint8List publicSpkiFromPkcs8(Uint8List pkcs8Der) =>
      _backend.publicSpkiFromPkcs8(pkcs8Der);

  /// Normalize stored private bytes to PKCS#8 DER (accepts the legacy EC blob).
  static Uint8List toPkcs8Der(
    Uint8List stored, {
    required DesktopKeyAlgorithm algorithm,
  }) {
    if (_looksLikeAsn1Sequence(stored)) {
      return stored;
    }
    if (_hasMagic(stored, _ecPrivMagic) &&
        algorithm == DesktopKeyAlgorithm.ecP256) {
      final body = stored.sublist(_ecPrivMagic.length);
      return _backend.ecP256FromScalar(body.sublist(0, 32)).pkcs8Der;
    }
    throw const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.corruptRecord,
      message: 'unrecognized private key encoding',
    );
  }

  /// Encrypt PKCS#8 PrivateKeyInfo as PBES2-AES-256-CBC EncryptedPrivateKeyInfo.
  static Uint8List encryptPkcs8Pbes2(
    Uint8List privateKeyPkcs8Der,
    Uint8List passphrase, {
    required int iterations,
  }) =>
      _backend.encryptPkcs8(
        privateKeyPkcs8Der,
        passphrase,
        iterations: iterations,
      );

  /// Decrypt EncryptedPrivateKeyInfo (PBES2) or legacy FSS-EPK1.
  static Uint8List decryptEncryptedPrivateKey(
    Uint8List encryptedKey,
    Uint8List passphrase,
  ) {
    final der = _maybeUnwrapPem(encryptedKey, 'ENCRYPTED PRIVATE KEY');
    if (_hasMagic(der, _fssEpk1)) {
      return _decryptFssEpk1(der, passphrase);
    }
    try {
      return _backend.decryptPkcs8(der, passphrase);
    } on DesktopSecureStorageException {
      rethrow;
    } catch (_) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.invalidConfiguration,
        message: 'wrong passphrase or unsupported encrypted private key',
      );
    }
  }

  static Uint8List toPem(Uint8List der, String label) {
    final b64 = base64.encode(der);
    final buf = StringBuffer('-----BEGIN $label-----\n');
    for (var i = 0; i < b64.length; i += 64) {
      buf.writeln(b64.substring(i, min(i + 64, b64.length)));
    }
    buf.writeln('-----END $label-----');
    return Uint8List.fromList(utf8.encode(buf.toString()));
  }

  /// Sign [data] with the PKCS#8 private key. RSA keys sign PKCS#1 v1.5 for
  /// both [SignatureAlgorithm.rsaPkcs1Sha256] and the PSS value.
  static Uint8List sign(
    Uint8List privateKeyPkcs8Der,
    Uint8List data, {
    required DesktopKeyAlgorithm keyAlgorithm,
    required SignatureAlgorithm signatureAlgorithm,
  }) =>
      _backend.sign(privateKeyPkcs8Der, data, algorithm: keyAlgorithm);

  /// Build a PKCS#10 CertificationRequest DER, signed by the private key.
  ///
  /// The request carries the public key of [privateKeyPkcs8Der].
  /// [publicKeySpkiDer], [algorithm], and [dnsNames] are accepted for API
  /// compatibility; SANs are not encoded.
  static Uint8List createPkcs10Csr({
    required Uint8List privateKeyPkcs8Der,
    required Uint8List publicKeySpkiDer,
    required DesktopKeyAlgorithm algorithm,
    required String subjectDn,
    List<String> dnsNames = const <String>[],
  }) =>
      _backend.createCsr(privateKeyPkcs8Der, subjectDn);

  // --- helpers ---

  static bool _looksLikeAsn1Sequence(Uint8List bytes) =>
      bytes.isNotEmpty && bytes[0] == 0x30;

  static bool _hasMagic(Uint8List bytes, String magic) {
    final m = utf8.encode(magic);
    if (bytes.length < m.length) {
      return false;
    }
    for (var i = 0; i < m.length; i++) {
      if (bytes[i] != m[i]) {
        return false;
      }
    }
    return true;
  }

  static Uint8List _decryptFssEpk1(Uint8List der, Uint8List passphrase) {
    var offset = _fssEpk1.length;
    final iterations = ByteData.sublistView(der, offset, offset + 4)
        .getUint32(0, Endian.little);
    offset += 4;
    final saltLen = der[offset++];
    final salt = der.sublist(offset, offset + saltLen);
    offset += saltLen;
    final nonceLen = der[offset++];
    final nonce = der.sublist(offset, offset + nonceLen);
    offset += nonceLen;
    final tagLen = der[offset++];
    final tag = der.sublist(offset, offset + tagLen);
    offset += tagLen;
    final ctLen = ByteData.sublistView(der, offset, offset + 4)
        .getUint32(0, Endian.little);
    offset += 4;
    final ciphertext = der.sublist(offset, offset + ctLen);
    final key = _backend.pbkdf2HmacSha256(passphrase, salt, iterations, 32);
    return _backend.aes256GcmDecrypt(
      key: key,
      nonce: nonce,
      ciphertext: ciphertext,
      tag: tag,
    );
  }

  static Uint8List _maybeUnwrapPem(Uint8List bytes, String label) {
    final text = utf8.decode(bytes, allowMalformed: true);
    if (!text.contains('BEGIN $label')) {
      return bytes;
    }
    final body = text
        .split(RegExp(r'\r?\n'))
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty && !l.startsWith('-----'))
        .join();
    return Uint8List.fromList(base64.decode(body));
  }
}

/// Generated key material for desktop private keys.
class DesktopKeyMaterial {
  DesktopKeyMaterial({
    required this.algorithm,
    required this.privateKeyPkcs8Der,
    required this.publicKeySpkiDer,
  });

  final DesktopKeyAlgorithm algorithm;
  final Uint8List privateKeyPkcs8Der;
  final Uint8List publicKeySpkiDer;
}
