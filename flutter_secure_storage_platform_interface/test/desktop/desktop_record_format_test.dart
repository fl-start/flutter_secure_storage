import 'dart:typed_data';

import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  const codec = DesktopRecordCodec();

  DesktopSecureRecord sample({
    int nonceLen = 12,
    int tagLen = 16,
    int wrappedLen = 32,
    int ctLen = 8,
    int aadLen = 4,
    List<int>? keyHash,
  }) {
    return DesktopSecureRecord(
      formatVersion: kDesktopRecordFormatVersion,
      providerId: DesktopRecordProviderId.windowsDpapi,
      flags: DesktopRecordFlags.migratedFromLegacy,
      algorithmId: 1,
      keyIdHash: Uint8List.fromList(keyHash ?? List<int>.filled(32, 7)),
      createdAtMillis: 1700000000000,
      nonce: Uint8List.fromList(List<int>.generate(nonceLen, (i) => i)),
      tag: Uint8List.fromList(List<int>.generate(tagLen, (i) => i + 1)),
      wrappedKey: Uint8List.fromList(List<int>.generate(wrappedLen, (i) => i)),
      ciphertext: Uint8List.fromList(List<int>.generate(ctLen, (i) => 9)),
      aad: Uint8List.fromList(List<int>.generate(aadLen, (i) => 3)),
    );
  }

  test('round-trips a valid record', () {
    final encoded = codec.encode(sample());
    final decoded = codec.decode(encoded);
    expect(decoded.providerId, DesktopRecordProviderId.windowsDpapi);
    expect(decoded.nonce.length, 12);
    expect(decoded.tag.length, 16);
    expect(decoded.isMachineScoped, isFalse);
    expect(decoded.flags & DesktopRecordFlags.migratedFromLegacy, isNonZero);
  });

  test('rejects truncated header', () {
    expect(
      () => codec.decode(Uint8List.fromList(const [0x46, 0x53, 0x53])),
      throwsA(
        isA<DesktopSecureStorageException>().having(
          (e) => e.code,
          'code',
          DesktopSecureStorageErrorCode.corruptRecord,
        ),
      ),
    );
  });

  test('rejects bad magic', () {
    final bytes = codec.encode(sample());
    bytes[0] = 0x00;
    expect(
      () => codec.decode(bytes),
      throwsA(isA<DesktopSecureStorageException>()),
    );
  });

  test('rejects zero nonce length via mutate', () {
    final bytes = codec.encode(sample());
    final view = ByteData.sublistView(bytes);
    view.setUint16(56, 0, Endian.little);
    expect(
      () => codec.decode(bytes),
      throwsA(isA<DesktopSecureStorageException>()),
    );
  });

  test('rejects trailing bytes', () {
    final bytes = codec.encode(sample());
    final padded = Uint8List(bytes.length + 1)..setAll(0, bytes);
    expect(
      () => codec.decode(padded),
      throwsA(isA<DesktopSecureStorageException>()),
    );
  });

  test('fuzz truncated / random buffers do not throw non-typed errors', () {
    final encoded = codec.encode(sample());
    for (var i = 0; i < encoded.length; i++) {
      final slice = Uint8List.fromList(encoded.sublist(0, i));
      try {
        codec.decode(slice);
      } on DesktopSecureStorageException catch (e) {
        expect(e.code, DesktopSecureStorageErrorCode.corruptRecord);
      }
    }
    final rng = List<int>.generate(200, (i) => (i * 37 + 11) & 0xff);
    try {
      codec.decode(Uint8List.fromList(rng));
    } on DesktopSecureStorageException catch (e) {
      expect(e.code, DesktopSecureStorageErrorCode.corruptRecord);
    }
  });

  test('verifyKeyId matches normalized id', () {
    final hash = keyIdSha256('app.account.key');
    final record = sample(keyHash: hash);
    codec.verifyKeyId(record, 'app.account.key');
    expect(
      () => codec.verifyKeyId(record, 'app.account.other'),
      throwsA(isA<DesktopSecureStorageException>()),
    );
  });
}
