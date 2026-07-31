import 'dart:typed_data';

import 'desktop_errors.dart';
import 'desktop_key_id.dart';

/// FSS1 magic bytes.
const List<int> kDesktopRecordMagic = <int>[0x46, 0x53, 0x53, 0x31]; // FSS1

/// Current format version.
const int kDesktopRecordFormatVersion = 1;

/// Maximum accepted record size (16 MiB).
const int kDesktopRecordMaxSize = 16 * 1024 * 1024;

/// Fixed header size before variable fields (excluding optional crc usage).
const int kDesktopRecordHeaderSize = 70;

/// Provider identifiers embedded in records.
abstract final class DesktopRecordProviderId {
  static const int windowsDpapi = 1;
  static const int windowsPlatformCrypto = 2;
  static const int windowsSoftwareCng = 3;
  static const int macOsKeychain = 4;
  static const int macOsSecureEnclave = 5;
  static const int linuxSecretService = 6;
  static const int linuxTpm2 = 7;
  static const int linuxSystemdCreds = 8;
  static const int linuxProtectedFile = 9;
}

/// Record flags.
abstract final class DesktopRecordFlags {
  static const int machineScoped = 1 << 0;
  static const int hardwareWrapped = 1 << 1;
  static const int exportablePrivateKey = 1 << 2;
  static const int userPresenceRequired = 1 << 3;
  static const int migratedFromLegacy = 1 << 4;
}

/// Parsed FSS1 record (ciphertext still encrypted).
class DesktopSecureRecord {
  const DesktopSecureRecord({
    required this.formatVersion,
    required this.providerId,
    required this.flags,
    required this.algorithmId,
    required this.keyIdHash,
    required this.createdAtMillis,
    required this.nonce,
    required this.tag,
    required this.wrappedKey,
    required this.ciphertext,
    required this.aad,
  });

  final int formatVersion;
  final int providerId;
  final int flags;
  final int algorithmId;
  final Uint8List keyIdHash;
  final int createdAtMillis;
  final Uint8List nonce;
  final Uint8List tag;
  final Uint8List wrappedKey;
  final Uint8List ciphertext;
  final Uint8List aad;

  bool get isMachineScoped => (flags & DesktopRecordFlags.machineScoped) != 0;
  bool get isHardwareWrapped =>
      (flags & DesktopRecordFlags.hardwareWrapped) != 0;
}

/// Encodes / decodes FSS1 records without native padding assumptions.
class DesktopRecordCodec {
  const DesktopRecordCodec();

  /// Serializes [record] to bytes.
  Uint8List encode(DesktopSecureRecord record) {
    final nonceLen = record.nonce.length;
    final tagLen = record.tag.length;
    final wrappedLen = record.wrappedKey.length;
    final ctLen = record.ciphertext.length;
    final aadLen = record.aad.length;

    _checkLengths(
      nonceLen: nonceLen,
      tagLen: tagLen,
      wrappedLen: wrappedLen,
      ctLen: ctLen,
      aadLen: aadLen,
    );

    final total = kDesktopRecordHeaderSize +
        nonceLen +
        tagLen +
        wrappedLen +
        ctLen +
        aadLen;
    if (total > kDesktopRecordMaxSize) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'record exceeds maximum size',
      );
    }

    final out = ByteData(total);
    final bytes = out.buffer.asUint8List();
    bytes.setRange(0, 4, kDesktopRecordMagic);
    out.setUint16(4, record.formatVersion, Endian.little);
    out.setUint16(6, record.providerId, Endian.little);
    out.setUint32(8, record.flags, Endian.little);
    out.setUint16(12, record.algorithmId, Endian.little);
    out.setUint16(14, 0, Endian.little);
    if (record.keyIdHash.length != 32) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'key_id_hash must be 32 bytes',
      );
    }
    bytes.setRange(16, 48, record.keyIdHash);
    out.setUint64(48, record.createdAtMillis, Endian.little);
    out.setUint16(56, nonceLen, Endian.little);
    out.setUint16(58, tagLen, Endian.little);
    out.setUint32(60, wrappedLen, Endian.little);
    out.setUint32(64, ctLen, Endian.little);
    out.setUint16(68, aadLen, Endian.little);

    var offset = kDesktopRecordHeaderSize;
    bytes.setRange(offset, offset + nonceLen, record.nonce);
    offset += nonceLen;
    bytes.setRange(offset, offset + tagLen, record.tag);
    offset += tagLen;
    bytes.setRange(offset, offset + wrappedLen, record.wrappedKey);
    offset += wrappedLen;
    bytes.setRange(offset, offset + ctLen, record.ciphertext);
    offset += ctLen;
    bytes.setRange(offset, offset + aadLen, record.aad);
    return bytes;
  }

  /// Parses bytes into a [DesktopSecureRecord].
  DesktopSecureRecord decode(Uint8List input) {
    if (input.length < kDesktopRecordHeaderSize) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'record truncated: header incomplete',
      );
    }
    if (input.length > kDesktopRecordMaxSize) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'record exceeds maximum size',
      );
    }
    for (var i = 0; i < 4; i++) {
      if (input[i] != kDesktopRecordMagic[i]) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.corruptRecord,
          message: 'invalid record magic',
        );
      }
    }

    final view = ByteData.sublistView(input);
    final version = view.getUint16(4, Endian.little);
    if (version != kDesktopRecordFormatVersion) {
      throw DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'unsupported format version $version',
      );
    }

    final providerId = view.getUint16(6, Endian.little);
    final flags = view.getUint32(8, Endian.little);
    final algorithmId = view.getUint16(12, Endian.little);
    final keyIdHash = Uint8List.fromList(input.sublist(16, 48));
    final createdAt = view.getUint64(48, Endian.little);
    final nonceLen = view.getUint16(56, Endian.little);
    final tagLen = view.getUint16(58, Endian.little);
    final wrappedLen = view.getUint32(60, Endian.little);
    final ctLen = view.getUint32(64, Endian.little);
    final aadLen = view.getUint16(68, Endian.little);

    _checkLengths(
      nonceLen: nonceLen,
      tagLen: tagLen,
      wrappedLen: wrappedLen,
      ctLen: ctLen,
      aadLen: aadLen,
    );

    final expected = kDesktopRecordHeaderSize +
        nonceLen +
        tagLen +
        wrappedLen +
        ctLen +
        aadLen;
    if (input.length < expected) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'record truncated: payload incomplete',
      );
    }
    if (input.length > expected) {
      // Forward-compatible: ignore trailing unknown bytes only if equal? Spec
      // says reject unknown trailing for v1 strictness.
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'record has unexpected trailing bytes',
      );
    }

    var offset = kDesktopRecordHeaderSize;
    Uint8List take(int len) {
      final slice = Uint8List.fromList(input.sublist(offset, offset + len));
      offset += len;
      return slice;
    }

    return DesktopSecureRecord(
      formatVersion: version,
      providerId: providerId,
      flags: flags,
      algorithmId: algorithmId,
      keyIdHash: keyIdHash,
      createdAtMillis: createdAt,
      nonce: take(nonceLen),
      tag: take(tagLen),
      wrappedKey: take(wrappedLen),
      ciphertext: take(ctLen),
      aad: take(aadLen),
    );
  }

  /// Returns true if [input] begins with FSS1 magic.
  bool hasMagic(Uint8List input) {
    if (input.length < 4) {
      return false;
    }
    for (var i = 0; i < 4; i++) {
      if (input[i] != kDesktopRecordMagic[i]) {
        return false;
      }
    }
    return true;
  }

  /// Verifies the record's key_id_hash matches [keyId].
  void verifyKeyId(DesktopSecureRecord record, String keyId) {
    final expected = keyIdSha256(keyId);
    if (expected.length != record.keyIdHash.length) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'key id hash mismatch',
      );
    }
    var diff = 0;
    for (var i = 0; i < expected.length; i++) {
      diff |= expected[i] ^ record.keyIdHash[i];
    }
    if (diff != 0) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'key id hash mismatch',
      );
    }
  }

  void _checkLengths({
    required int nonceLen,
    required int tagLen,
    required int wrappedLen,
    required int ctLen,
    required int aadLen,
  }) {
    if (nonceLen <= 0 || nonceLen > 255) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'invalid nonce length',
      );
    }
    if (tagLen <= 0 || tagLen > 255) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'invalid tag length',
      );
    }
    if (wrappedLen < 0 || ctLen < 0 || aadLen < 0) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'negative length',
      );
    }
    // Overflow check for 32-bit-ish sums.
    final sum = kDesktopRecordHeaderSize +
        nonceLen +
        tagLen +
        wrappedLen +
        ctLen +
        aadLen;
    if (sum < 0 || sum > kDesktopRecordMaxSize) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'length overflow',
      );
    }
  }
}
