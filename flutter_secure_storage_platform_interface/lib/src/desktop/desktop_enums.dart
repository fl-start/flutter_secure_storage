/// Protection policy for desktop secure storage / private keys.
enum DesktopSecureStorageProtection {
  /// OS-recommended secure storage for the platform.
  platformDefault,

  /// Prefer TPM / Secure Enclave / equivalent; fall back and report it.
  hardwareBackedPreferred,

  /// Require a hardware-backed provider; never silently fall back.
  hardwareBackedRequired,

  /// OS-protected or encrypted-filesystem storage without requiring hardware.
  softwareProtected,
}

/// Immutable export policy selected at private-key creation.
enum PrivateKeyExportPolicy {
  /// Secure default. Private material never leaves the provider.
  nonExportable,

  /// Explicit opt-in. Private key may be exported only as encrypted PKCS#8.
  exportableEncrypted,
}

/// Supported desktop asymmetric algorithms.
enum DesktopKeyAlgorithm {
  rsa2048,
  rsa3072,
  ecP256,
  ed25519,
}

/// Public-key encoding for [DesktopPrivateKeyManager.getPublicKey].
enum PublicKeyEncoding {
  spkiDer,
  spkiPem,
}

/// Encrypted private-key export encoding (PKCS#8 EncryptedPrivateKeyInfo).
enum PrivateKeyEncoding {
  pemPkcs8,
  derPkcs8,
}

/// Password-based KDF for encrypted PKCS#8 export.
enum PrivateKeyKdf {
  pbkdf2Sha256,
  argon2id,
}

/// Signature algorithms for [DesktopPrivateKeyManager.sign].
enum SignatureAlgorithm {
  rsaPssSha256,
  rsaPkcs1Sha256,
  ecdsaSha256,
  ed25519,
}
