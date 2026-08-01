import 'desktop_enums.dart';

/// Effective desktop security capabilities for the current process/host.
///
/// Distinguishes private-key hardware residence from storage wrapping hardware.
class DesktopSecureStorageCapabilities {
  /// Creates a capabilities snapshot.
  const DesktopSecureStorageCapabilities({
    required this.platform,
    required this.availableProviders,
    required this.selectedProvider,
    required this.hardwareAvailable,
    required this.storageProtectionHardwareBacked,
    required this.privateKeyHardwareBacked,
    required this.supportsNonExportableKeys,
    required this.supportsExportableKeys,
    required this.supportsUserPresence,
    required this.supportsMachineScope,
    required this.supportsCsrGeneration,
    required this.supportedAlgorithms,
    required this.supportedExportFormats,
    this.fallbackReason,
    this.sameUserCompromiseResistant = false,
    this.rootCompromiseResistant = false,
  });

  /// Platform id: `android`, `ios`, `windows`, `macos`, or `linux`.
  final String platform;

  /// Providers discovered at runtime.
  final List<String> availableProviders;

  /// Provider selected for the current policy / default.
  final String selectedProvider;

  /// Whether any hardware-backed provider is available.
  final bool hardwareAvailable;

  /// Whether wrapping / DEK protection uses hardware.
  final bool storageProtectionHardwareBacked;

  /// Whether private keys themselves reside in hardware.
  final bool privateKeyHardwareBacked;

  /// Whether non-exportable keys are supported.
  final bool supportsNonExportableKeys;

  /// Whether exportableEncrypted keys are supported.
  final bool supportsExportableKeys;

  /// Whether user-presence / biometric gating is available.
  final bool supportsUserPresence;

  /// Whether machine-scoped storage is available.
  final bool supportsMachineScope;

  /// Whether CSR generation without export is available.
  final bool supportsCsrGeneration;

  /// Algorithms supported by the selected provider.
  final List<DesktopKeyAlgorithm> supportedAlgorithms;

  /// Export encodings supported for exportable keys.
  final List<PrivateKeyEncoding> supportedExportFormats;

  /// Why a preferred hardware provider was not used, if applicable.
  final String? fallbackReason;

  /// Whether same-user malware can typically extract secrets.
  final bool sameUserCompromiseResistant;

  /// Whether root/admin compromise is resisted by the selected backend.
  final bool rootCompromiseResistant;

  /// Deserializes a method-channel map.
  factory DesktopSecureStorageCapabilities.fromMap(Map<Object?, Object?> map) {
    List<String> stringList(Object? value) =>
        (value as List<Object?>? ?? const <Object?>[])
            .map((e) => e.toString())
            .toList(growable: false);

    List<DesktopKeyAlgorithm> algorithms(Object? value) {
      final names = stringList(value);
      return DesktopKeyAlgorithm.values
          .where((a) => names.contains(a.name))
          .toList(growable: false);
    }

    List<PrivateKeyEncoding> encodings(Object? value) {
      final names = stringList(value);
      return PrivateKeyEncoding.values
          .where((a) => names.contains(a.name))
          .toList(growable: false);
    }

    return DesktopSecureStorageCapabilities(
      platform: map['platform']?.toString() ?? 'unknown',
      availableProviders: stringList(map['availableProviders']),
      selectedProvider: map['selectedProvider']?.toString() ?? 'none',
      hardwareAvailable: map['hardwareAvailable'] == true,
      storageProtectionHardwareBacked:
          map['storageProtectionHardwareBacked'] == true,
      privateKeyHardwareBacked: map['privateKeyHardwareBacked'] == true,
      supportsNonExportableKeys: map['supportsNonExportableKeys'] == true,
      supportsExportableKeys: map['supportsExportableKeys'] == true,
      supportsUserPresence: map['supportsUserPresence'] == true,
      supportsMachineScope: map['supportsMachineScope'] == true,
      supportsCsrGeneration: map['supportsCsrGeneration'] == true,
      supportedAlgorithms: algorithms(map['supportedAlgorithms']),
      supportedExportFormats: encodings(map['supportedExportFormats']),
      fallbackReason: map['fallbackReason']?.toString(),
      sameUserCompromiseResistant: map['sameUserCompromiseResistant'] == true,
      rootCompromiseResistant: map['rootCompromiseResistant'] == true,
    );
  }

  /// Serializes for method channels / tests.
  Map<String, Object?> toMap() => <String, Object?>{
        'platform': platform,
        'availableProviders': availableProviders,
        'selectedProvider': selectedProvider,
        'hardwareAvailable': hardwareAvailable,
        'storageProtectionHardwareBacked': storageProtectionHardwareBacked,
        'privateKeyHardwareBacked': privateKeyHardwareBacked,
        'supportsNonExportableKeys': supportsNonExportableKeys,
        'supportsExportableKeys': supportsExportableKeys,
        'supportsUserPresence': supportsUserPresence,
        'supportsMachineScope': supportsMachineScope,
        'supportsCsrGeneration': supportsCsrGeneration,
        'supportedAlgorithms':
            supportedAlgorithms.map((e) => e.name).toList(growable: false),
        'supportedExportFormats':
            supportedExportFormats.map((e) => e.name).toList(growable: false),
        'fallbackReason': fallbackReason,
        'sameUserCompromiseResistant': sameUserCompromiseResistant,
        'rootCompromiseResistant': rootCompromiseResistant,
      };
}
