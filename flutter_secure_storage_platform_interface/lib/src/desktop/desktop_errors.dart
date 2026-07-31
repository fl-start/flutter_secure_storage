/// Typed error codes for desktop secure storage / private-key operations.
///
/// Diagnostic [DesktopSecureStorageException.details] must never include
/// private keys, passphrases, plaintext values, or decrypted master keys.
enum DesktopSecureStorageErrorCode {
  providerUnavailable,
  hardwareRequiredButUnavailable,
  algorithmUnsupported,
  keyAlreadyExists,
  keyNotFound,
  keyNotExportable,
  invalidExportPassphrase,
  authenticationRequired,
  authenticationCancelled,
  accessDenied,
  corruptRecord,
  migrationFailed,
  tpmPolicyMismatch,
  keyUnwrapFailed,
  invalidConfiguration,
  unsafeFilesystemPermissions,
  unsupportedPlatform,
  unknown,
}

/// Platform-independent exception for desktop secure-storage failures.
class DesktopSecureStorageException implements Exception {
  /// Creates a typed desktop secure-storage exception.
  const DesktopSecureStorageException({
    required this.code,
    required this.message,
    this.provider,
    this.nativeStatusCode,
    this.details = const <String, Object?>{},
  });

  /// Stable error code.
  final DesktopSecureStorageErrorCode code;

  /// Safe human-readable message (no secrets).
  final String message;

  /// Provider name when known (e.g. `MS_PLATFORM_CRYPTO_PROVIDER`).
  final String? provider;

  /// Native status / OS error code when available.
  final int? nativeStatusCode;

  /// Additional safe diagnostic metadata.
  final Map<String, Object?> details;

  /// Parses a method-channel error code string.
  static DesktopSecureStorageErrorCode parseCode(String? raw) {
    if (raw == null || raw.isEmpty) {
      return DesktopSecureStorageErrorCode.unknown;
    }
    for (final value in DesktopSecureStorageErrorCode.values) {
      if (value.name == raw || value.name.toLowerCase() == raw.toLowerCase()) {
        return value;
      }
    }
    return DesktopSecureStorageErrorCode.unknown;
  }

  @override
  String toString() {
    final buffer = StringBuffer('DesktopSecureStorageException(${code.name}): $message');
    if (provider != null) {
      buffer.write(' provider=$provider');
    }
    if (nativeStatusCode != null) {
      buffer.write(' nativeStatusCode=$nativeStatusCode');
    }
    return buffer.toString();
  }
}
