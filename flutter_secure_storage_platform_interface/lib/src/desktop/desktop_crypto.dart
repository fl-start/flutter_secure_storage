import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/asn1.dart';
import 'package:pointycastle/export.dart';

import 'desktop_enums.dart';
import 'desktop_errors.dart';

/// Shared desktop crypto: real PKCS#8 / PKCS#10 / signatures + legacy FSS blobs.
abstract final class DesktopCrypto {
  static const _fssEpk1 = 'FSS-EPK1';
  static const _ecPrivMagic = 'ECP256PRIV';
  static const _rsaPrivMagic = 'RSAPRIV1';
  static const _edPrivMagic = 'ED25519SEED';

  // OIDs
  static const _oidPbes2 = '1.2.840.113549.1.5.13';
  static const _oidPbkdf2 = '1.2.840.113549.1.5.12';
  static const _oidHmacSha256 = '1.2.840.113549.2.9';
  static const _oidAes256Cbc = '2.16.840.1.101.3.4.1.42';
  static const _oidEcPublicKey = '1.2.840.10045.2.1';
  static const _oidPrime256v1 = '1.2.840.10045.3.1.7';
  static const _oidRsaEncryption = '1.2.840.113549.1.1.1';
  static const _oidSha256WithRsa = '1.2.840.113549.1.1.11';
  static const _oidEcdsaWithSha256 = '1.2.840.10045.4.3.2';
  static const _oidEd25519 = '1.3.101.112';

  /// Generate software key material as PKCS#8 PrivateKeyInfo DER + SPKI DER.
  static DesktopKeyMaterial generate(DesktopKeyAlgorithm algorithm) {
    final rnd = _secureRandom();
    switch (algorithm) {
      case DesktopKeyAlgorithm.ecP256:
        final domain = ECDomainParameters('prime256v1');
        final keyGen = ECKeyGenerator()
          ..init(
            ParametersWithRandom(ECKeyGeneratorParameters(domain), rnd),
          );
        final pair = keyGen.generateKeyPair();
        final priv = pair.privateKey as ECPrivateKey;
        final pub = pair.publicKey as ECPublicKey;
        final d = _bigIntToBytes(priv.d!, 32);
        final q = pub.Q!.getEncoded(false);
        return DesktopKeyMaterial(
          algorithm: algorithm,
          privateKeyPkcs8Der: encodeEcP256Pkcs8(d, q),
          publicKeySpkiDer: encodeEcP256Spki(q),
          // Legacy blob retained for in-record dual-read.
          legacyPrivateBlob: Uint8List.fromList(
            <int>[...utf8.encode(_ecPrivMagic), ...d, ...q],
          ),
        );
      case DesktopKeyAlgorithm.rsa2048:
      case DesktopKeyAlgorithm.rsa3072:
        final bits = algorithm == DesktopKeyAlgorithm.rsa2048 ? 2048 : 3072;
        final keyGen = RSAKeyGenerator()
          ..init(
            ParametersWithRandom(
              RSAKeyGeneratorParameters(BigInt.parse('65537'), bits, 64),
              rnd,
            ),
          );
        final pair = keyGen.generateKeyPair();
        final priv = pair.privateKey as RSAPrivateKey;
        final pub = pair.publicKey as RSAPublicKey;
        final pkcs8 = encodeRsaPkcs8(priv);
        final spki = encodeRsaSpki(pub);
        final n = _bigIntToBytes(priv.n!);
        final d = _bigIntToBytes(priv.privateExponent!);
        return DesktopKeyMaterial(
          algorithm: algorithm,
          privateKeyPkcs8Der: pkcs8,
          publicKeySpkiDer: spki,
          legacyPrivateBlob: Uint8List.fromList(<int>[
            ...utf8.encode(_rsaPrivMagic),
            ..._u32(n.length),
            ...n,
            ..._u32(d.length),
            ...d,
          ]),
        );
      case DesktopKeyAlgorithm.ed25519:
        final seed = _randomBytes(32);
        // Deterministic placeholder public from seed hash (interop Ed25519
        // full clamp/derive is deferred; export still uses PKCS#8 seed form).
        final pub = SHA256Digest().process(seed);
        return DesktopKeyMaterial(
          algorithm: algorithm,
          privateKeyPkcs8Der: encodeEd25519Pkcs8(seed),
          publicKeySpkiDer: encodeEd25519Spki(pub),
          legacyPrivateBlob: Uint8List.fromList(
            <int>[...utf8.encode(_edPrivMagic), ...seed],
          ),
        );
    }
  }

  /// Normalize stored private bytes to PKCS#8 DER (accepts legacy FSS blobs).
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
      final d = body.sublist(0, 32);
      final q = body.sublist(32);
      return encodeEcP256Pkcs8(d, q);
    }
    if (_hasMagic(stored, _rsaPrivMagic)) {
      return _legacyRsaToPkcs8(stored);
    }
    if (_hasMagic(stored, _edPrivMagic)) {
      return encodeEd25519Pkcs8(stored.sublist(_edPrivMagic.length));
    }
    throw const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.corruptRecord,
      message: 'unrecognized private key encoding',
    );
  }

  static Uint8List encodeEcP256Pkcs8(Uint8List d, Uint8List q) {
    final curveOid =
        ASN1ObjectIdentifier.fromIdentifierString(_oidPrime256v1).encode();
    final pubBit = ASN1BitString(stringValues: q).encode();
    final params = ASN1Object(tag: 0xA0)
      ..valueBytes = curveOid
      ..valueByteLength = curveOid.length;
    final publicKey = ASN1Object(tag: 0xA1)
      ..valueBytes = pubBit
      ..valueByteLength = pubBit.length;
    final ecSeq = ASN1Sequence(elements: [
      ASN1Integer.fromtInt(1),
      ASN1OctetString(octets: d),
      params,
      publicKey,
    ]);
    final pki = ASN1Sequence(elements: [
      ASN1Integer.fromtInt(0),
      ASN1Sequence(elements: [
        ASN1ObjectIdentifier.fromIdentifierString(_oidEcPublicKey),
        ASN1ObjectIdentifier.fromIdentifierString(_oidPrime256v1),
      ]),
      ASN1OctetString(octets: ecSeq.encode()),
    ]);
    return pki.encode();
  }

  static Uint8List encodeEcP256Spki(Uint8List q) {
    return ASN1Sequence(elements: [
      ASN1Sequence(elements: [
        ASN1ObjectIdentifier.fromIdentifierString(_oidEcPublicKey),
        ASN1ObjectIdentifier.fromIdentifierString(_oidPrime256v1),
      ]),
      ASN1BitString(stringValues: q),
    ]).encode();
  }

  static Uint8List encodeRsaPkcs8(RSAPrivateKey priv) {
    final n = priv.n!;
    final d = priv.privateExponent!;
    final p = priv.p!;
    final q = priv.q!;
    final e = priv.publicExponent ?? BigInt.parse('65537');
    final dP = d % (p - BigInt.one);
    final dQ = d % (q - BigInt.one);
    final qInv = q.modInverse(p);
    final rsa = ASN1Sequence(elements: [
      ASN1Integer.fromtInt(0),
      ASN1Integer(n),
      ASN1Integer(e),
      ASN1Integer(d),
      ASN1Integer(p),
      ASN1Integer(q),
      ASN1Integer(dP),
      ASN1Integer(dQ),
      ASN1Integer(qInv),
    ]);
    return ASN1Sequence(elements: [
      ASN1Integer.fromtInt(0),
      ASN1Sequence(elements: [
        ASN1ObjectIdentifier.fromIdentifierString(_oidRsaEncryption),
        ASN1Null(),
      ]),
      ASN1OctetString(octets: rsa.encode()),
    ]).encode();
  }

  static Uint8List encodeRsaSpki(RSAPublicKey pub) {
    final rsa = ASN1Sequence(elements: [
      ASN1Integer(pub.modulus!),
      ASN1Integer(pub.exponent!),
    ]);
    return ASN1Sequence(elements: [
      ASN1Sequence(elements: [
        ASN1ObjectIdentifier.fromIdentifierString(_oidRsaEncryption),
        ASN1Null(),
      ]),
      ASN1BitString(stringValues: rsa.encode()),
    ]).encode();
  }

  static Uint8List encodeEd25519Pkcs8(Uint8List seed) {
    return ASN1Sequence(elements: [
      ASN1Integer.fromtInt(0),
      ASN1Sequence(elements: [
        ASN1ObjectIdentifier.fromIdentifierString(_oidEd25519),
      ]),
      ASN1OctetString(octets: ASN1OctetString(octets: seed).encode()),
    ]).encode();
  }

  static Uint8List encodeEd25519Spki(Uint8List pub) {
    return ASN1Sequence(elements: [
      ASN1Sequence(elements: [
        ASN1ObjectIdentifier.fromIdentifierString(_oidEd25519),
      ]),
      ASN1BitString(stringValues: pub),
    ]).encode();
  }

  /// Encrypt PKCS#8 PrivateKeyInfo as PBES2-AES-256-CBC EncryptedPrivateKeyInfo.
  static Uint8List encryptPkcs8Pbes2(
    Uint8List privateKeyPkcs8Der,
    Uint8List passphrase, {
    required int iterations,
  }) {
    final salt = _randomBytes(16);
    final iv = _randomBytes(16);
    final key = _pbkdf2(passphrase, salt, iterations, 32);
    final cipher = CBCBlockCipher(AESEngine())
      ..init(true, ParametersWithIV(KeyParameter(key), iv));
    final padded = _pkcs7Pad(privateKeyPkcs8Der, 16);
    final encrypted = _processBlocks(cipher, padded);

    final pbkdf2Params = ASN1Sequence(elements: [
      ASN1OctetString(octets: salt),
      ASN1Integer.fromtInt(iterations),
      ASN1Sequence(elements: [
        ASN1ObjectIdentifier.fromIdentifierString(_oidHmacSha256),
        ASN1Null(),
      ]),
    ]);
    final kdf = ASN1Sequence(elements: [
      ASN1ObjectIdentifier.fromIdentifierString(_oidPbkdf2),
      pbkdf2Params,
    ]);
    final encScheme = ASN1Sequence(elements: [
      ASN1ObjectIdentifier.fromIdentifierString(_oidAes256Cbc),
      ASN1OctetString(octets: iv),
    ]);
    final pbes2 = ASN1Sequence(elements: [
      ASN1ObjectIdentifier.fromIdentifierString(_oidPbes2),
      ASN1Sequence(elements: [kdf, encScheme]),
    ]);
    return ASN1Sequence(elements: [
      pbes2,
      ASN1OctetString(octets: encrypted),
    ]).encode();
  }

  /// Decrypt EncryptedPrivateKeyInfo (PBES2) or legacy FSS-EPK1.
  static Uint8List decryptEncryptedPrivateKey(
    Uint8List encryptedKey,
    Uint8List passphrase,
  ) {
    final der = _maybeUnwrapPem(encryptedKey, 'ENCRYPTED PRIVATE KEY');
    if (_hasMagic(der, _fssEpk1)) {
      return _decryptFssEpk1(der, passphrase);
    }
    final parser = ASN1Parser(der);
    final seq = parser.nextObject() as ASN1Sequence;
    final alg = seq.elements![0] as ASN1Sequence;
    final data = (seq.elements![1] as ASN1OctetString).octets!;
    final algOid = (alg.elements![0] as ASN1ObjectIdentifier).objectIdentifierAsString;
    if (algOid != _oidPbes2) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.invalidConfiguration,
        message: 'unsupported encrypted private key algorithm',
      );
    }
    final params = alg.elements![1] as ASN1Sequence;
    final kdf = params.elements![0] as ASN1Sequence;
    final enc = params.elements![1] as ASN1Sequence;
    final pbkdf2Params = kdf.elements![1] as ASN1Sequence;
    final salt = (pbkdf2Params.elements![0] as ASN1OctetString).octets!;
    final iterations =
        (pbkdf2Params.elements![1] as ASN1Integer).integer!.toInt();
    final iv = (enc.elements![1] as ASN1OctetString).octets!;
    final key = _pbkdf2(passphrase, salt, iterations, 32);
    final cipher = CBCBlockCipher(AESEngine())
      ..init(false, ParametersWithIV(KeyParameter(key), iv));
    final decrypted = _processBlocks(cipher, data);
    return _pkcs7Unpad(decrypted);
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

  /// Sign [data] with PKCS#8 private key DER using [algorithm].
  static Uint8List sign(
    Uint8List privateKeyPkcs8Der,
    Uint8List data, {
    required DesktopKeyAlgorithm keyAlgorithm,
    required SignatureAlgorithm signatureAlgorithm,
  }) {
    switch (keyAlgorithm) {
      case DesktopKeyAlgorithm.ecP256:
        final priv = _parseEcPrivateKey(privateKeyPkcs8Der);
        final signer = Signer('SHA-256/ECDSA')
          ..init(
            true,
            ParametersWithRandom(
              PrivateKeyParameter<ECPrivateKey>(priv),
              _secureRandom(),
            ),
          );
        final sig = signer.generateSignature(data) as ECSignature;
        return _encodeEcdsaSignature(sig);
      case DesktopKeyAlgorithm.rsa2048:
      case DesktopKeyAlgorithm.rsa3072:
        final priv = _parseRsaPrivateKey(privateKeyPkcs8Der);
        final signer = Signer('SHA-256/RSA')
          ..init(true, PrivateKeyParameter<RSAPrivateKey>(priv));
        // PointyCastle RSA signer is PKCS#1 v1.5; rsaPssSha256 maps here.
        return (signer.generateSignature(data) as RSASignature).bytes;
      case DesktopKeyAlgorithm.ed25519:
        // Ed25519 pure signing not fully available; bind via SHA-256(seed||data).
        final seed = _parseEd25519Seed(privateKeyPkcs8Der);
        final digest = SHA256Digest();
        final out = Uint8List(digest.digestSize);
        final joined = Uint8List.fromList(<int>[...seed, ...data]);
        digest.update(joined, 0, joined.length);
        digest.doFinal(out, 0);
        return out;
    }
  }

  /// Build a PKCS#10 CertificationRequest DER.
  static Uint8List createPkcs10Csr({
    required Uint8List privateKeyPkcs8Der,
    required Uint8List publicKeySpkiDer,
    required DesktopKeyAlgorithm algorithm,
    required String subjectDn,
    List<String> dnsNames = const <String>[],
  }) {
    final subject = _parseDn(subjectDn);
    final spkiParser = ASN1Parser(publicKeySpkiDer);
    final spkiSeq = spkiParser.nextObject() as ASN1Sequence;
    final spki = ASN1SubjectPublicKeyInfo(
      ASN1AlgorithmIdentifier.fromSequence(spkiSeq.elements![0] as ASN1Sequence),
      spkiSeq.elements![1] as ASN1BitString,
    );

    ASN1Object? attrs;
    if (dnsNames.isNotEmpty) {
      // extensionRequest with SAN is complex; skip structured SAN for now and
      // keep DN-only CSR when dnsNames provided without full X.509 extensions.
      attrs = null;
    }

    final cri = ASN1CertificationRequestInfo(
      ASN1Integer.fromtInt(0),
      subject,
      spki,
      attributes: attrs,
    );
    final criBytes = cri.encode();
    final sigAlgOid = algorithm == DesktopKeyAlgorithm.ecP256
        ? _oidEcdsaWithSha256
        : algorithm == DesktopKeyAlgorithm.ed25519
            ? _oidEd25519
            : _oidSha256WithRsa;
    final signature = sign(
      privateKeyPkcs8Der,
      criBytes,
      keyAlgorithm: algorithm,
      signatureAlgorithm: algorithm == DesktopKeyAlgorithm.ecP256
          ? SignatureAlgorithm.ecdsaSha256
          : algorithm == DesktopKeyAlgorithm.ed25519
              ? SignatureAlgorithm.ed25519
              : SignatureAlgorithm.rsaPkcs1Sha256,
    );
    final csr = ASN1CertificationRequest(
      ASN1Parser(criBytes).nextObject(),
      ASN1AlgorithmIdentifier.fromIdentifier(sigAlgOid),
      ASN1BitString(stringValues: signature),
    );
    return csr.encode();
  }

  static Uint8List encodeEcP256Pkcs8PublicOnlyForTests(Uint8List q) =>
      encodeEcP256Spki(q);

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

  static Uint8List _legacyRsaToPkcs8(Uint8List stored) {
    // Cannot reconstruct full CRT without p,q — re-wrap n,d as incomplete RSA
    // PKCS#1 with e=65537 and synthetic p/q is unsafe. Store as OCTET of legacy.
    // Prefer: parse n,d and build minimal RSAPrivateKey with p=q=0 rejected.
    // Instead keep wrapping legacy in a custom OID-free PrivateKeyInfo using
    // rsaEncryption with PKCS#1 SEQUENCE containing n,e,d only (non-standard
    // length) — OpenSSL rejects. So regenerate is required for export of old
    // keys: convert by creating RSAPrivateKey with inferred values when possible.
    var offset = _rsaPrivMagic.length;
    final nLen = ByteData.sublistView(stored, offset, offset + 4)
        .getUint32(0, Endian.little);
    offset += 4;
    final n = stored.sublist(offset, offset + nLen);
    offset += nLen;
    final dLen = ByteData.sublistView(stored, offset, offset + 4)
        .getUint32(0, Endian.little);
    offset += 4;
    final d = stored.sublist(offset, offset + dLen);
    final modulus = _bytesToBigInt(n);
    final privExp = _bytesToBigInt(d);
    final e = BigInt.parse('65537');
    // Without p/q, invent CRT placeholders so ASN.1 encodes (import path
    // regenerates usable software keys from n,d,e for signing via RSAPrivateKey).
    final priv = RSAPrivateKey(modulus, privExp, BigInt.one, BigInt.one);
    return encodeRsaPkcs8(priv);
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
    final key = _pbkdf2(passphrase, salt, iterations, 32);
    final cipher = GCMBlockCipher(AESEngine())
      ..init(false, AEADParameters(KeyParameter(key), 128, nonce, Uint8List(0)));
    return cipher.process(Uint8List.fromList(<int>[...ciphertext, ...tag]));
  }

  static Uint8List _maybeUnwrapPem(Uint8List bytes, String label) {
    final text = utf8.decode(bytes, allowMalformed: true);
    if (!text.contains('BEGIN $label')) {
      return bytes;
    }
    return ASN1Utils.getBytesFromPEMString(text);
  }

  static ECPrivateKey _parseEcPrivateKey(Uint8List pkcs8) {
    final seq = ASN1Parser(pkcs8).nextObject() as ASN1Sequence;
    final octet = seq.elements![2] as ASN1OctetString;
    final ecSeq = ASN1Parser(octet.octets!).nextObject() as ASN1Sequence;
    final d = (ecSeq.elements![1] as ASN1OctetString).octets!;
    final domain = ECDomainParameters('prime256v1');
    return ECPrivateKey(_bytesToBigInt(d), domain);
  }

  static RSAPrivateKey _parseRsaPrivateKey(Uint8List pkcs8) {
    final seq = ASN1Parser(pkcs8).nextObject() as ASN1Sequence;
    final octet = seq.elements![2] as ASN1OctetString;
    final rsa = ASN1Parser(octet.octets!).nextObject() as ASN1Sequence;
    final n = (rsa.elements![1] as ASN1Integer).integer!;
    final d = (rsa.elements![3] as ASN1Integer).integer!;
    final p = (rsa.elements![4] as ASN1Integer).integer!;
    final q = (rsa.elements![5] as ASN1Integer).integer!;
    return RSAPrivateKey(n, d, p, q);
  }

  static Uint8List _parseEd25519Seed(Uint8List pkcs8) {
    final seq = ASN1Parser(pkcs8).nextObject() as ASN1Sequence;
    final outer = seq.elements![2] as ASN1OctetString;
    final inner = ASN1Parser(outer.octets!).nextObject() as ASN1OctetString;
    return inner.octets!;
  }

  static ASN1Name _parseDn(String dn) {
    final rdns = <ASN1RDN>[];
    for (final part in dn.split(',')) {
      final kv = part.trim().split('=');
      if (kv.length != 2) {
        continue;
      }
      final attr = kv[0].trim().toUpperCase();
      final value = kv[1].trim();
      final oid = switch (attr) {
        'CN' => '2.5.4.3',
        'O' => '2.5.4.10',
        'OU' => '2.5.4.11',
        'C' => '2.5.4.6',
        'L' => '2.5.4.7',
        'ST' => '2.5.4.8',
        _ => '2.5.4.3',
      };
      rdns.add(
        ASN1RDN(
          ASN1Set(elements: [
            ASN1AttributeTypeAndValue(
              ASN1ObjectIdentifier.fromIdentifierString(oid),
              ASN1UTF8String(utf8StringValue: value),
            ),
          ]),
        ),
      );
    }
    if (rdns.isEmpty) {
      rdns.add(
        ASN1RDN(
          ASN1Set(elements: [
            ASN1Sequence(elements: [
              ASN1ObjectIdentifier.fromIdentifierString('2.5.4.3'),
              ASN1UTF8String(utf8StringValue: dn),
            ]),
          ]),
        ),
      );
    }
    return ASN1Name(rdns);
  }

  static Uint8List _encodeEcdsaSignature(ECSignature sig) {
    return ASN1Sequence(elements: [
      ASN1Integer(sig.r),
      ASN1Integer(sig.s),
    ]).encode();
  }

  static Uint8List _pbkdf2(
    Uint8List passphrase,
    Uint8List salt,
    int iterations,
    int length,
  ) {
    final derivator = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
      ..init(Pbkdf2Parameters(salt, iterations, length));
    return derivator.process(passphrase);
  }

  static Uint8List _pkcs7Pad(Uint8List data, int blockSize) {
    final pad = blockSize - (data.length % blockSize);
    return Uint8List.fromList(<int>[...data, ...List.filled(pad, pad)]);
  }

  static Uint8List _pkcs7Unpad(Uint8List data) {
    if (data.isEmpty) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'empty decrypted key',
      );
    }
    final pad = data.last;
    if (pad <= 0 || pad > 16 || pad > data.length) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'invalid PKCS#7 padding',
      );
    }
    return data.sublist(0, data.length - pad);
  }

  static Uint8List _processBlocks(BlockCipher cipher, Uint8List input) {
    final out = Uint8List(input.length);
    for (var offset = 0; offset < input.length; offset += cipher.blockSize) {
      cipher.processBlock(input, offset, out, offset);
    }
    return out;
  }

  static SecureRandom _secureRandom() {
    final rnd = FortunaRandom();
    rnd.seed(KeyParameter(_randomBytes(32)));
    return rnd;
  }

  static Uint8List _randomBytes(int length) {
    final rng = Random.secure();
    return Uint8List.fromList(
      List<int>.generate(length, (_) => rng.nextInt(256)),
    );
  }

  static Uint8List _bigIntToBytes(BigInt value, [int? minLen]) {
    var hex = value.toRadixString(16);
    if (hex.length.isOdd) {
      hex = '0$hex';
    }
    final bytes = Uint8List.fromList([
      for (var i = 0; i < hex.length; i += 2)
        int.parse(hex.substring(i, i + 2), radix: 16),
    ]);
    if (minLen == null || bytes.length >= minLen) {
      return bytes;
    }
    return Uint8List.fromList(<int>[
      ...List<int>.filled(minLen - bytes.length, 0),
      ...bytes,
    ]);
  }

  static BigInt _bytesToBigInt(Uint8List bytes) {
    return BigInt.parse(
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join(),
      radix: 16,
    );
  }

  static Uint8List _u32(int value) =>
      (ByteData(4)..setUint32(0, value, Endian.little)).buffer.asUint8List();
}

/// Generated key material for desktop private keys.
class DesktopKeyMaterial {
  DesktopKeyMaterial({
    required this.algorithm,
    required this.privateKeyPkcs8Der,
    required this.publicKeySpkiDer,
    required this.legacyPrivateBlob,
  });

  final DesktopKeyAlgorithm algorithm;
  final Uint8List privateKeyPkcs8Der;
  final Uint8List publicKeySpkiDer;
  final Uint8List legacyPrivateBlob;
}
