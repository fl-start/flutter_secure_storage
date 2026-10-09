import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';

/// Minimal DER encoding for the TPM key path: SubjectPublicKeyInfo from CNG
/// public blobs, ECDSA signature re-encoding, and PKCS#10 assembly.
///
/// Software keys never use this; their DER comes from the installed
/// [DesktopCryptoBackend].
abstract final class WindowsDer {
  static const _oidEcPublicKey = '1.2.840.10045.2.1';
  static const _oidPrime256v1 = '1.2.840.10045.3.1.7';
  static const _oidRsaEncryption = '1.2.840.113549.1.1.1';
  static const _oidEcdsaWithSha256 = '1.2.840.10045.4.3.2';
  static const _oidSha256WithRsa = '1.2.840.113549.1.1.11';
  static const _oidRsaPss = '1.2.840.113549.1.1.10';
  static const _oidSha256 = '2.16.840.1.101.3.4.2.1';
  static const _oidMgf1 = '1.2.840.113549.1.1.8';

  static const _dnAttributes = <String, String>{
    'CN': '2.5.4.3',
    'SERIALNUMBER': '2.5.4.5',
    'C': '2.5.4.6',
    'L': '2.5.4.7',
    'ST': '2.5.4.8',
    'STREET': '2.5.4.9',
    'O': '2.5.4.10',
    'OU': '2.5.4.11',
    'T': '2.5.4.12',
    'TITLE': '2.5.4.12',
    'DC': '0.9.2342.19200300.100.1.25',
    'UID': '0.9.2342.19200300.100.1.1',
    'EMAIL': '1.2.840.113549.1.9.1',
    'EMAILADDRESS': '1.2.840.113549.1.9.1',
  };

  // --- SubjectPublicKeyInfo -------------------------------------------------

  /// SPKI for an EC P-256 public point given as big-endian X and Y.
  static Uint8List ecP256Spki(Uint8List x, Uint8List y) {
    final point = Uint8List(1 + x.length + y.length)
      ..[0] = 0x04
      ..setRange(1, 1 + x.length, x)
      ..setRange(1 + x.length, 1 + x.length + y.length, y);
    return sequence([
      sequence([oid(_oidEcPublicKey), oid(_oidPrime256v1)]),
      bitString(point),
    ]);
  }

  /// SPKI for an RSA public key given as big-endian modulus and exponent.
  static Uint8List rsaSpki(Uint8List modulus, Uint8List exponent) {
    final rsaPublicKey = sequence([
      unsignedInteger(modulus),
      unsignedInteger(exponent),
    ]);
    return sequence([
      sequence([oid(_oidRsaEncryption), nullValue()]),
      bitString(rsaPublicKey),
    ]);
  }

  // --- Signatures -----------------------------------------------------------

  /// ASN.1 `ECDSA-Sig-Value` from the `r || s` form CNG returns.
  static Uint8List ecdsaRawToDer(Uint8List raw) {
    if (raw.isEmpty || raw.length.isOdd) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.unknown,
        message: 'unexpected ECDSA signature length',
      );
    }
    final half = raw.length ~/ 2;
    return sequence([
      unsignedInteger(Uint8List.sublistView(raw, 0, half)),
      unsignedInteger(Uint8List.sublistView(raw, half)),
    ]);
  }

  /// `AlgorithmIdentifier` for the signature a key produces.
  static Uint8List signatureAlgorithmIdentifier(
    DesktopKeyAlgorithm keyAlgorithm,
    SignatureAlgorithm signatureAlgorithm,
  ) {
    switch (keyAlgorithm) {
      case DesktopKeyAlgorithm.ecP256:
        return sequence([oid(_oidEcdsaWithSha256)]);
      case DesktopKeyAlgorithm.rsa2048:
      case DesktopKeyAlgorithm.rsa3072:
        if (signatureAlgorithm == SignatureAlgorithm.rsaPssSha256) {
          final sha256 = sequence([oid(_oidSha256), nullValue()]);
          return sequence([
            oid(_oidRsaPss),
            sequence([
              contextConstructed(0, sha256),
              contextConstructed(1, sequence([oid(_oidMgf1), sha256])),
              contextConstructed(2, integer(32)),
            ]),
          ]);
        }
        return sequence([oid(_oidSha256WithRsa), nullValue()]);
      case DesktopKeyAlgorithm.ed25519:
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.algorithmUnsupported,
          message: 'ed25519 is not supported by Windows TPM providers',
        );
    }
  }

  // --- PKCS#10 --------------------------------------------------------------

  /// `CertificationRequestInfo` DER: version 0, subject, key, no attributes.
  static Uint8List certificationRequestInfo({
    required String subjectDn,
    required Uint8List publicKeySpkiDer,
  }) {
    return sequence([
      integer(0),
      distinguishedName(subjectDn),
      publicKeySpkiDer,
      contextConstructed(0, Uint8List(0)),
    ]);
  }

  /// `CertificationRequest` DER from the signed request info.
  static Uint8List certificationRequest({
    required Uint8List requestInfo,
    required Uint8List signatureAlgorithm,
    required Uint8List signature,
  }) {
    return sequence([requestInfo, signatureAlgorithm, bitString(signature)]);
  }

  /// X.501 `Name` from `CN=device,O=Example` (RDNs kept in the given order).
  ///
  /// Backslash escapes a separator. Attribute types are the common short
  /// names or a dotted OID.
  static Uint8List distinguishedName(String dn) {
    final rdns = <Uint8List>[];
    for (final part in _splitUnescaped(dn.trim(), ',')) {
      final trimmed = part.trim();
      if (trimmed.isEmpty) {
        continue;
      }
      final eq = _indexOfUnescaped(trimmed, '=');
      if (eq <= 0) {
        throw DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.invalidConfiguration,
          message: 'invalid distinguished name component',
          details: <String, Object?>{'component': trimmed},
        );
      }
      final type = trimmed.substring(0, eq).trim();
      final value = _unescape(trimmed.substring(eq + 1).trim());
      final attrOid = _attributeOid(type);
      final upper = type.toUpperCase();
      final Uint8List encodedValue;
      if (upper == 'C') {
        encodedValue = _tagged(0x13, ascii.encode(value));
      } else if (upper == 'DC' ||
          upper == 'EMAIL' ||
          upper == 'EMAILADDRESS' ||
          attrOid == '1.2.840.113549.1.9.1') {
        encodedValue = _tagged(0x16, ascii.encode(value));
      } else {
        encodedValue = _tagged(0x0C, utf8.encode(value));
      }
      rdns.add(
        set([
          sequence([oid(attrOid), encodedValue]),
        ]),
      );
    }
    return sequence(rdns);
  }

  static String _attributeOid(String type) {
    final known = _dnAttributes[type.toUpperCase()];
    if (known != null) {
      return known;
    }
    if (RegExp(r'^\d+(\.\d+)+$').hasMatch(type)) {
      return type;
    }
    throw DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.invalidConfiguration,
      message: 'unsupported distinguished name attribute',
      details: <String, Object?>{'attribute': type},
    );
  }

  static List<String> _splitUnescaped(String input, String separator) {
    final parts = <String>[];
    final current = StringBuffer();
    var escaped = false;
    for (final ch in input.split('')) {
      if (escaped) {
        current.write('\\$ch');
        escaped = false;
      } else if (ch == r'\') {
        escaped = true;
      } else if (ch == separator) {
        parts.add(current.toString());
        current.clear();
      } else {
        current.write(ch);
      }
    }
    if (escaped) {
      current.write(r'\');
    }
    parts.add(current.toString());
    return parts;
  }

  static int _indexOfUnescaped(String input, String needle) {
    var escaped = false;
    for (var i = 0; i < input.length; i++) {
      final ch = input[i];
      if (escaped) {
        escaped = false;
      } else if (ch == r'\') {
        escaped = true;
      } else if (ch == needle) {
        return i;
      }
    }
    return -1;
  }

  static String _unescape(String input) {
    final out = StringBuffer();
    var escaped = false;
    for (final ch in input.split('')) {
      if (escaped) {
        out.write(ch);
        escaped = false;
      } else if (ch == r'\') {
        escaped = true;
      } else {
        out.write(ch);
      }
    }
    return out.toString();
  }

  // --- DER primitives -------------------------------------------------------

  /// SEQUENCE of already-encoded [items].
  static Uint8List sequence(List<Uint8List> items) =>
      _tagged(0x30, _concat(items));

  /// SET of already-encoded [items], kept in the given order.
  static Uint8List set(List<Uint8List> items) => _tagged(0x31, _concat(items));

  /// NULL.
  static Uint8List nullValue() => Uint8List.fromList(const [0x05, 0x00]);

  /// BIT STRING with no unused bits.
  static Uint8List bitString(Uint8List bytes) => _tagged(
        0x03,
        Uint8List(bytes.length + 1)..setRange(1, bytes.length + 1, bytes),
      );

  /// Constructed context-specific tag `[tagNumber]` around [content].
  static Uint8List contextConstructed(int tagNumber, Uint8List content) =>
      _tagged(0xA0 | tagNumber, content);

  /// INTEGER from a non-negative [value].
  static Uint8List integer(int value) {
    if (value < 0) {
      throw ArgumentError.value(value, 'value', 'must be non-negative');
    }
    final bytes = <int>[];
    var v = value;
    do {
      bytes.insert(0, v & 0xFF);
      v >>= 8;
    } while (v > 0);
    return unsignedInteger(Uint8List.fromList(bytes));
  }

  /// INTEGER from big-endian unsigned magnitude bytes.
  static Uint8List unsignedInteger(Uint8List magnitude) {
    var start = 0;
    while (start < magnitude.length - 1 && magnitude[start] == 0) {
      start++;
    }
    final trimmed = magnitude.isEmpty
        ? Uint8List.fromList(const [0])
        : Uint8List.sublistView(magnitude, start);
    if (trimmed[0] & 0x80 != 0) {
      return _tagged(
        0x02,
        Uint8List(trimmed.length + 1)..setRange(1, trimmed.length + 1, trimmed),
      );
    }
    return _tagged(0x02, trimmed);
  }

  /// OBJECT IDENTIFIER from dotted notation.
  static Uint8List oid(String dotted) {
    final arcs = dotted.split('.').map(int.parse).toList(growable: false);
    if (arcs.length < 2) {
      throw ArgumentError.value(dotted, 'dotted', 'OID needs two arcs');
    }
    final body = <int>[arcs[0] * 40 + arcs[1]];
    for (final arc in arcs.skip(2)) {
      final chunk = <int>[arc & 0x7F];
      var v = arc >> 7;
      while (v > 0) {
        chunk.insert(0, (v & 0x7F) | 0x80);
        v >>= 7;
      }
      body.addAll(chunk);
    }
    return _tagged(0x06, Uint8List.fromList(body));
  }

  static Uint8List _tagged(int tag, List<int> content) {
    final length = _length(content.length);
    return Uint8List(1 + length.length + content.length)
      ..[0] = tag
      ..setRange(1, 1 + length.length, length)
      ..setRange(
        1 + length.length,
        1 + length.length + content.length,
        content,
      );
  }

  static List<int> _length(int length) {
    if (length < 0x80) {
      return [length];
    }
    final bytes = <int>[];
    var v = length;
    while (v > 0) {
      bytes.insert(0, v & 0xFF);
      v >>= 8;
    }
    return [0x80 | bytes.length, ...bytes];
  }

  static Uint8List _concat(List<Uint8List> items) {
    final out = BytesBuilder(copy: false);
    for (final item in items) {
      out.add(item);
    }
    return out.toBytes();
  }
}
