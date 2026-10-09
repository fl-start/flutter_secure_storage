import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';
import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';

import 'package:flutter_secure_storage_windows/src/desktop/windows_der.dart';

/// TPM-resident key operations used by `WindowsDesktopKeyManager`.
///
/// Keys are created inside the TPM through the Microsoft Platform Crypto
/// Provider and never leave it: only the public key, signatures, and the
/// provider key name are visible to Dart.
abstract interface class WindowsTpmKeyBackend {
  /// True when a TPM 2.0 is reachable through the platform crypto provider.
  bool probe();

  /// Creates a non-exportable signing key named [keyName].
  ///
  /// Returns the SubjectPublicKeyInfo DER of the new key.
  Uint8List createKey({
    required String keyName,
    required DesktopKeyAlgorithm algorithm,
    required bool machineScoped,
  });

  /// SubjectPublicKeyInfo DER read from the TPM key.
  Uint8List publicKeySpki({
    required String keyName,
    required DesktopKeyAlgorithm algorithm,
    required bool machineScoped,
  });

  /// Signs SHA-256 of [data]. ECDSA signatures are ASN.1 DER; RSA uses PSS
  /// for [SignatureAlgorithm.rsaPssSha256] and PKCS#1 v1.5 otherwise.
  Uint8List sign({
    required String keyName,
    required DesktopKeyAlgorithm algorithm,
    required bool machineScoped,
    required Uint8List data,
    required SignatureAlgorithm signatureAlgorithm,
  });

  /// Deletes the key. A key that no longer exists is not an error.
  void deleteKey({required String keyName, required bool machineScoped});
}

/// [WindowsTpmKeyBackend] over `ncrypt.dll` and the Microsoft Platform Crypto
/// Provider.
final class NcryptTpmKeyBackend implements WindowsTpmKeyBackend {
  /// Creates the backend; `ncrypt.dll` loads on first use.
  NcryptTpmKeyBackend();

  /// CNG key storage provider that keeps keys inside the TPM.
  static const providerName = 'Microsoft Platform Crypto Provider';

  static const _ncryptSilentFlag = 0x40;
  static const _ncryptMachineKeyFlag = 0x20;
  static const _ncryptAllowSigningFlag = 0x2;
  static const _bcryptPadPkcs1 = 0x2;
  static const _bcryptPadPss = 0x8;
  static const _eccPublicP256Magic = 0x31534345; // 'ECS1'
  static const _rsaPublicMagic = 0x31415352; // 'RSA1'

  static const _nteBadKeyset = 0x80090016;
  static const _nteExists = 0x8009000F;
  static const _nteNotSupported = 0x80090029;
  static const _nteBadAlgId = 0x80090008;
  static const _ntePerm = 0x80090010;
  static const _eAccessDenied = 0x80070005;

  _Ncrypt? _api;

  _Ncrypt get _ncrypt => _api ??= _Ncrypt.open();

  @override
  bool probe() {
    try {
      return using((arena) {
        final provider = _openProvider(arena);
        try {
          final type = _stringProperty(provider, 'PCP_PLATFORM_TYPE', arena);
          return type != null && type.contains('TPM-Version:2.0');
        } finally {
          _ncrypt.freeObject(provider);
        }
      });
    } on Object {
      return false;
    }
  }

  @override
  Uint8List createKey({
    required String keyName,
    required DesktopKeyAlgorithm algorithm,
    required bool machineScoped,
  }) {
    return using((arena) {
      final provider = _openProvider(arena);
      try {
        final phKey = arena<IntPtr>();
        _check(
          _ncrypt.createPersistedKey(
            provider,
            phKey,
            _algorithmId(algorithm).toNativeUtf16(allocator: arena),
            keyName.toNativeUtf16(allocator: arena),
            0,
            machineScoped ? _ncryptMachineKeyFlag : 0,
          ),
          'NCryptCreatePersistedKey',
        );
        final key = phKey.value;
        var finalized = false;
        try {
          final bits = _rsaBits(algorithm);
          if (bits != null) {
            _setDword(key, 'Length', bits, arena);
          }
          // Export policy 0: the key can never be exported, not even wrapped.
          _setDword(key, 'Export Policy', 0, arena);
          _setDword(key, 'Key Usage', _ncryptAllowSigningFlag, arena);
          _check(
            _ncrypt.finalizeKey(key, _ncryptSilentFlag),
            'NCryptFinalizeKey',
          );
          finalized = true;
          final spki = _exportPublicSpki(key, algorithm, arena);
          _ncrypt.freeObject(key);
          return spki;
        } catch (_) {
          // A finalized key is persisted; delete it so a failed create leaves
          // no orphan. NCryptDeleteKey frees the handle when it succeeds.
          if (!finalized || _ncrypt.deleteKey(key, 0) != 0) {
            _ncrypt.freeObject(key);
          }
          rethrow;
        }
      } finally {
        _ncrypt.freeObject(provider);
      }
    });
  }

  @override
  Uint8List publicKeySpki({
    required String keyName,
    required DesktopKeyAlgorithm algorithm,
    required bool machineScoped,
  }) {
    return _withKey(keyName, machineScoped, (key, arena) {
      return _exportPublicSpki(key, algorithm, arena);
    });
  }

  @override
  Uint8List sign({
    required String keyName,
    required DesktopKeyAlgorithm algorithm,
    required bool machineScoped,
    required Uint8List data,
    required SignatureAlgorithm signatureAlgorithm,
  }) {
    final digest = sha256Bytes(data);
    return _withKey(keyName, machineScoped, (key, arena) {
      final hash = arena<Uint8>(digest.length);
      hash.asTypedList(digest.length).setAll(0, digest);

      Pointer<Void> padding = nullptr;
      var flags = _ncryptSilentFlag;
      if (_rsaBits(algorithm) != null) {
        final hashAlg = 'SHA256'.toNativeUtf16(allocator: arena);
        if (signatureAlgorithm == SignatureAlgorithm.rsaPssSha256) {
          final pss = arena<_BcryptPssPaddingInfo>();
          pss.ref.pszAlgId = hashAlg;
          pss.ref.cbSalt = 32;
          padding = pss.cast();
          flags |= _bcryptPadPss;
        } else {
          final pkcs1 = arena<_BcryptPkcs1PaddingInfo>();
          pkcs1.ref.pszAlgId = hashAlg;
          padding = pkcs1.cast();
          flags |= _bcryptPadPkcs1;
        }
      }

      final size = arena<Uint32>();
      _check(
        _ncrypt.signHash(
          key,
          padding,
          hash,
          digest.length,
          nullptr,
          0,
          size,
          flags,
        ),
        'NCryptSignHash',
      );
      final out = arena<Uint8>(size.value);
      _check(
        _ncrypt.signHash(
          key,
          padding,
          hash,
          digest.length,
          out,
          size.value,
          size,
          flags,
        ),
        'NCryptSignHash',
      );
      final signature = Uint8List.fromList(out.asTypedList(size.value));
      if (algorithm == DesktopKeyAlgorithm.ecP256) {
        return WindowsDer.ecdsaRawToDer(signature);
      }
      return signature;
    });
  }

  @override
  void deleteKey({required String keyName, required bool machineScoped}) {
    using((arena) {
      final provider = _openProvider(arena);
      try {
        final phKey = arena<IntPtr>();
        final status = _ncrypt.openKey(
          provider,
          phKey,
          keyName.toNativeUtf16(allocator: arena),
          0,
          _openFlags(machineScoped),
        );
        if (_unsigned(status) == _nteBadKeyset) {
          return;
        }
        _check(status, 'NCryptOpenKey');
        final deleted = _ncrypt.deleteKey(phKey.value, 0);
        if (deleted != 0) {
          _ncrypt.freeObject(phKey.value);
          _check(deleted, 'NCryptDeleteKey');
        }
      } finally {
        _ncrypt.freeObject(provider);
      }
    });
  }

  // --- helpers --------------------------------------------------------------

  T _withKey<T>(
    String keyName,
    bool machineScoped,
    T Function(int key, Arena arena) body,
  ) {
    return using((arena) {
      final provider = _openProvider(arena);
      try {
        final phKey = arena<IntPtr>();
        _check(
          _ncrypt.openKey(
            provider,
            phKey,
            keyName.toNativeUtf16(allocator: arena),
            0,
            _openFlags(machineScoped),
          ),
          'NCryptOpenKey',
        );
        try {
          return body(phKey.value, arena);
        } finally {
          _ncrypt.freeObject(phKey.value);
        }
      } finally {
        _ncrypt.freeObject(provider);
      }
    });
  }

  int _openProvider(Arena arena) {
    final phProvider = arena<IntPtr>();
    _check(
      _ncrypt.openStorageProvider(
        phProvider,
        providerName.toNativeUtf16(allocator: arena),
        0,
      ),
      'NCryptOpenStorageProvider',
    );
    return phProvider.value;
  }

  int _openFlags(bool machineScoped) =>
      _ncryptSilentFlag | (machineScoped ? _ncryptMachineKeyFlag : 0);

  void _setDword(int handle, String property, int value, Arena arena) {
    final buffer = arena<Uint32>()..value = value;
    _check(
      _ncrypt.setProperty(
        handle,
        property.toNativeUtf16(allocator: arena),
        buffer.cast(),
        4,
        _ncryptSilentFlag,
      ),
      'NCryptSetProperty($property)',
    );
  }

  String? _stringProperty(int handle, String property, Arena arena) {
    final name = property.toNativeUtf16(allocator: arena);
    final size = arena<Uint32>();
    if (_ncrypt.getProperty(handle, name, nullptr, 0, size, 0) != 0 ||
        size.value == 0) {
      return null;
    }
    final out = arena<Uint8>(size.value);
    if (_ncrypt.getProperty(handle, name, out, size.value, size, 0) != 0) {
      return null;
    }
    return out
        .cast<Utf16>()
        .toDartString(length: size.value ~/ 2)
        .replaceAll('\u0000', '');
  }

  Uint8List _exportPublicSpki(
    int key,
    DesktopKeyAlgorithm algorithm,
    Arena arena,
  ) {
    final isRsa = _rsaBits(algorithm) != null;
    final blobType = (isRsa ? 'RSAPUBLICBLOB' : 'ECCPUBLICBLOB')
        .toNativeUtf16(allocator: arena);
    final size = arena<Uint32>();
    _check(
      _ncrypt.exportKey(key, 0, blobType, nullptr, nullptr, 0, size, 0),
      'NCryptExportKey',
    );
    final out = arena<Uint8>(size.value);
    _check(
      _ncrypt.exportKey(key, 0, blobType, nullptr, out, size.value, size, 0),
      'NCryptExportKey',
    );
    final blob = Uint8List.fromList(out.asTypedList(size.value));
    return isRsa ? _rsaSpkiFromBlob(blob) : _ecSpkiFromBlob(blob);
  }

  static Uint8List _ecSpkiFromBlob(Uint8List blob) {
    final view = ByteData.sublistView(blob);
    final magic = view.getUint32(0, Endian.little);
    final cbKey = view.getUint32(4, Endian.little);
    if (magic != _eccPublicP256Magic ||
        cbKey != 32 ||
        blob.length < 8 + 2 * cbKey) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'unexpected ECC public blob from TPM provider',
        provider: providerName,
      );
    }
    return WindowsDer.ecP256Spki(
      Uint8List.sublistView(blob, 8, 8 + cbKey),
      Uint8List.sublistView(blob, 8 + cbKey, 8 + 2 * cbKey),
    );
  }

  static Uint8List _rsaSpkiFromBlob(Uint8List blob) {
    final view = ByteData.sublistView(blob);
    final magic = view.getUint32(0, Endian.little);
    final cbPublicExp = view.getUint32(8, Endian.little);
    final cbModulus = view.getUint32(12, Endian.little);
    const header = 24;
    if (magic != _rsaPublicMagic ||
        blob.length < header + cbPublicExp + cbModulus) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'unexpected RSA public blob from TPM provider',
        provider: providerName,
      );
    }
    final exponent = Uint8List.sublistView(blob, header, header + cbPublicExp);
    final modulus = Uint8List.sublistView(
      blob,
      header + cbPublicExp,
      header + cbPublicExp + cbModulus,
    );
    return WindowsDer.rsaSpki(modulus, exponent);
  }

  static String _algorithmId(DesktopKeyAlgorithm algorithm) {
    switch (algorithm) {
      case DesktopKeyAlgorithm.ecP256:
        return 'ECDSA_P256';
      case DesktopKeyAlgorithm.rsa2048:
      case DesktopKeyAlgorithm.rsa3072:
        return 'RSA';
      case DesktopKeyAlgorithm.ed25519:
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.algorithmUnsupported,
          message: 'ed25519 is not supported by Windows TPM providers',
          provider: providerName,
        );
    }
  }

  static int? _rsaBits(DesktopKeyAlgorithm algorithm) => switch (algorithm) {
        DesktopKeyAlgorithm.rsa2048 => 2048,
        DesktopKeyAlgorithm.rsa3072 => 3072,
        _ => null,
      };

  static int _unsigned(int status) => status & 0xFFFFFFFF;

  static void _check(int status, String operation) {
    if (status == 0) {
      return;
    }
    final code = _unsigned(status);
    final errorCode = switch (code) {
      _nteBadKeyset => DesktopSecureStorageErrorCode.keyNotFound,
      _nteExists => DesktopSecureStorageErrorCode.keyAlreadyExists,
      _nteNotSupported ||
      _nteBadAlgId =>
        DesktopSecureStorageErrorCode.algorithmUnsupported,
      _ntePerm || _eAccessDenied => DesktopSecureStorageErrorCode.accessDenied,
      _ => DesktopSecureStorageErrorCode.providerUnavailable,
    };
    throw DesktopSecureStorageException(
      code: errorCode,
      message: '$operation failed',
      nativeStatusCode: code,
      provider: providerName,
    );
  }
}

final class _BcryptPkcs1PaddingInfo extends Struct {
  external Pointer<Utf16> pszAlgId;
}

final class _BcryptPssPaddingInfo extends Struct {
  external Pointer<Utf16> pszAlgId;

  @Uint32()
  external int cbSalt;
}

typedef _OpenStorageProviderDart = int Function(
  Pointer<IntPtr> phProvider,
  Pointer<Utf16> pszProviderName,
  int dwFlags,
);

typedef _CreatePersistedKeyDart = int Function(
  int hProvider,
  Pointer<IntPtr> phKey,
  Pointer<Utf16> pszAlgId,
  Pointer<Utf16> pszKeyName,
  int dwLegacyKeySpec,
  int dwFlags,
);

typedef _OpenKeyDart = int Function(
  int hProvider,
  Pointer<IntPtr> phKey,
  Pointer<Utf16> pszKeyName,
  int dwLegacyKeySpec,
  int dwFlags,
);

typedef _SetPropertyDart = int Function(
  int hObject,
  Pointer<Utf16> pszProperty,
  Pointer<Uint8> pbInput,
  int cbInput,
  int dwFlags,
);

typedef _GetPropertyDart = int Function(
  int hObject,
  Pointer<Utf16> pszProperty,
  Pointer<Uint8> pbOutput,
  int cbOutput,
  Pointer<Uint32> pcbResult,
  int dwFlags,
);

typedef _FinalizeKeyDart = int Function(int hKey, int dwFlags);

typedef _ExportKeyDart = int Function(
  int hKey,
  int hExportKey,
  Pointer<Utf16> pszBlobType,
  Pointer<Void> pParameterList,
  Pointer<Uint8> pbOutput,
  int cbOutput,
  Pointer<Uint32> pcbResult,
  int dwFlags,
);

typedef _SignHashDart = int Function(
  int hKey,
  Pointer<Void> pPaddingInfo,
  Pointer<Uint8> pbHashValue,
  int cbHashValue,
  Pointer<Uint8> pbSignature,
  int cbSignature,
  Pointer<Uint32> pcbResult,
  int dwFlags,
);

typedef _DeleteKeyDart = int Function(int hKey, int dwFlags);

typedef _FreeObjectDart = int Function(int hObject);

/// `ncrypt.dll` entry points used by [NcryptTpmKeyBackend].
final class _Ncrypt {
  _Ncrypt._(DynamicLibrary lib)
      : openStorageProvider = lib.lookupFunction<
            Int32 Function(
              Pointer<IntPtr> phProvider,
              Pointer<Utf16> pszProviderName,
              Uint32 dwFlags,
            ),
            _OpenStorageProviderDart>('NCryptOpenStorageProvider'),
        createPersistedKey = lib.lookupFunction<
            Int32 Function(
              IntPtr hProvider,
              Pointer<IntPtr> phKey,
              Pointer<Utf16> pszAlgId,
              Pointer<Utf16> pszKeyName,
              Uint32 dwLegacyKeySpec,
              Uint32 dwFlags,
            ),
            _CreatePersistedKeyDart>('NCryptCreatePersistedKey'),
        openKey = lib.lookupFunction<
            Int32 Function(
              IntPtr hProvider,
              Pointer<IntPtr> phKey,
              Pointer<Utf16> pszKeyName,
              Uint32 dwLegacyKeySpec,
              Uint32 dwFlags,
            ),
            _OpenKeyDart>('NCryptOpenKey'),
        setProperty = lib.lookupFunction<
            Int32 Function(
              IntPtr hObject,
              Pointer<Utf16> pszProperty,
              Pointer<Uint8> pbInput,
              Uint32 cbInput,
              Uint32 dwFlags,
            ),
            _SetPropertyDart>(
          'NCryptSetProperty',
        ),
        getProperty = lib.lookupFunction<
            Int32 Function(
              IntPtr hObject,
              Pointer<Utf16> pszProperty,
              Pointer<Uint8> pbOutput,
              Uint32 cbOutput,
              Pointer<Uint32> pcbResult,
              Uint32 dwFlags,
            ),
            _GetPropertyDart>(
          'NCryptGetProperty',
        ),
        finalizeKey = lib.lookupFunction<
            Int32 Function(IntPtr hKey, Uint32 dwFlags), _FinalizeKeyDart>(
          'NCryptFinalizeKey',
        ),
        exportKey = lib.lookupFunction<
            Int32 Function(
              IntPtr hKey,
              IntPtr hExportKey,
              Pointer<Utf16> pszBlobType,
              Pointer<Void> pParameterList,
              Pointer<Uint8> pbOutput,
              Uint32 cbOutput,
              Pointer<Uint32> pcbResult,
              Uint32 dwFlags,
            ),
            _ExportKeyDart>(
          'NCryptExportKey',
        ),
        signHash = lib.lookupFunction<
            Int32 Function(
              IntPtr hKey,
              Pointer<Void> pPaddingInfo,
              Pointer<Uint8> pbHashValue,
              Uint32 cbHashValue,
              Pointer<Uint8> pbSignature,
              Uint32 cbSignature,
              Pointer<Uint32> pcbResult,
              Uint32 dwFlags,
            ),
            _SignHashDart>(
          'NCryptSignHash',
        ),
        deleteKey = lib.lookupFunction<
            Int32 Function(IntPtr hKey, Uint32 dwFlags), _DeleteKeyDart>(
          'NCryptDeleteKey',
        ),
        freeObject =
            lib.lookupFunction<Int32 Function(IntPtr hObject), _FreeObjectDart>(
          'NCryptFreeObject',
        );

  factory _Ncrypt.open() => _Ncrypt._(DynamicLibrary.open('ncrypt.dll'));

  final _OpenStorageProviderDart openStorageProvider;
  final _CreatePersistedKeyDart createPersistedKey;
  final _OpenKeyDart openKey;
  final _SetPropertyDart setProperty;
  final _GetPropertyDart getProperty;
  final _FinalizeKeyDart finalizeKey;
  final _ExportKeyDart exportKey;
  final _SignHashDart signHash;
  final _DeleteKeyDart deleteKey;
  final _FreeObjectDart freeObject;
}
