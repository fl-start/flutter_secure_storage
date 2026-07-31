import 'dart:convert';
import 'dart:typed_data';

import 'desktop_errors.dart';

final _keyIdPattern = RegExp(r'^[A-Za-z0-9][A-Za-z0-9._@/-]{0,251}$');

/// Normalizes and validates a desktop key id for keystore / filename use.
///
/// Rejects path traversal and control characters. Returns the trimmed id.
String normalizeAndValidateKeyId(String keyId) {
  final normalized = keyId.trim();
  if (normalized.isEmpty) {
    throw const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.invalidConfiguration,
      message: 'keyId must be non-empty',
    );
  }
  if (normalized.contains('..') ||
      normalized.contains(r'\') ||
      normalized.contains('\u0000')) {
    throw const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.invalidConfiguration,
      message: 'keyId contains unsafe path characters',
    );
  }
  if (!_keyIdPattern.hasMatch(normalized)) {
    throw const DesktopSecureStorageException(
      code: DesktopSecureStorageErrorCode.invalidConfiguration,
      message:
          'keyId must be 1-252 chars of [A-Za-z0-9._@/-] and start alphanumerically',
    );
  }
  return normalized;
}

/// Filename-safe token derived from a key id (not trusted as metadata).
String sanitizeKeyIdForFilename(String keyId) {
  final normalized = normalizeAndValidateKeyId(keyId);
  return normalized.replaceAll(RegExp(r'[^A-Za-z0-9._-]'), '_');
}

/// SHA-256 of the UTF-8 normalized key id (for record headers).
Uint8List keyIdSha256(String keyId) {
  final normalized = normalizeAndValidateKeyId(keyId);
  return sha256Bytes(utf8.encode(normalized));
}

/// SHA-256 digest used for key-id hashing / AAD binding only.
Uint8List sha256Bytes(List<int> data) {
  var h0 = 0x6a09e667;
  var h1 = 0xbb67ae85;
  var h2 = 0x3c6ef372;
  var h3 = 0xa54ff53a;
  var h4 = 0x510e527f;
  var h5 = 0x9b05688c;
  var h6 = 0x1f83d9ab;
  var h7 = 0x5be0cd19;

  const k = <int>[
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  int rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & 0xffffffff;

  final bitLen = data.length * 8;
  final withOne = <int>[...data, 0x80];
  while ((withOne.length % 64) != 56) {
    withOne.add(0);
  }
  for (var i = 7; i >= 0; i--) {
    withOne.add((bitLen >> (i * 8)) & 0xff);
  }

  for (var offset = 0; offset < withOne.length; offset += 64) {
    final w = List<int>.filled(64, 0);
    for (var i = 0; i < 16; i++) {
      final j = offset + i * 4;
      w[i] = (withOne[j] << 24) |
          (withOne[j + 1] << 16) |
          (withOne[j + 2] << 8) |
          withOne[j + 3];
    }
    for (var i = 16; i < 64; i++) {
      final s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      final s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff;
    }
    var a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7;
    for (var i = 0; i < 64; i++) {
      final S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      final ch = (e & f) ^ ((~e) & g);
      final temp1 = (h + S1 + ch + k[i] + w[i]) & 0xffffffff;
      final S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      final maj = (a & b) ^ (a & c) ^ (b & c);
      final temp2 = (S0 + maj) & 0xffffffff;
      h = g;
      g = f;
      f = e;
      e = (d + temp1) & 0xffffffff;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) & 0xffffffff;
    }
    h0 = (h0 + a) & 0xffffffff;
    h1 = (h1 + b) & 0xffffffff;
    h2 = (h2 + c) & 0xffffffff;
    h3 = (h3 + d) & 0xffffffff;
    h4 = (h4 + e) & 0xffffffff;
    h5 = (h5 + f) & 0xffffffff;
    h6 = (h6 + g) & 0xffffffff;
    h7 = (h7 + h) & 0xffffffff;
  }

  final out = ByteData(32);
  out.setUint32(0, h0);
  out.setUint32(4, h1);
  out.setUint32(8, h2);
  out.setUint32(12, h3);
  out.setUint32(16, h4);
  out.setUint32(20, h5);
  out.setUint32(24, h6);
  out.setUint32(28, h7);
  return out.buffer.asUint8List();
}
