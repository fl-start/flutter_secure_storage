import 'dart:typed_data';

/// Just enough DER reading for tests to take signed structures apart.
abstract final class DerReader {
  /// Encoded children of the constructed element [der].
  static List<Uint8List> children(Uint8List der) {
    final (contentStart, contentEnd) = _bounds(der, 0);
    final out = <Uint8List>[];
    var offset = contentStart;
    while (offset < contentEnd) {
      final (_, childEnd) = _bounds(der, offset);
      if (childEnd > contentEnd) {
        throw StateError('malformed DER');
      }
      out.add(Uint8List.sublistView(der, offset, childEnd));
      offset = childEnd;
    }
    return out;
  }

  /// Content of a BIT STRING without its unused-bits byte.
  static Uint8List bitStringContent(Uint8List der) {
    final (start, end) = _bounds(der, 0);
    return Uint8List.sublistView(der, start + 1, end);
  }

  /// Content bytes of the element [der].
  static Uint8List content(Uint8List der) {
    final (start, end) = _bounds(der, 0);
    return Uint8List.sublistView(der, start, end);
  }

  static (int, int) _bounds(Uint8List der, int offset) {
    var i = offset + 1;
    var length = der[i++];
    if (length & 0x80 != 0) {
      final count = length & 0x7F;
      length = 0;
      for (var n = 0; n < count; n++) {
        length = (length << 8) | der[i++];
      }
    }
    return (i, i + length);
  }
}
