part of '../flutter_secure_storage.dart';

/// Specific options for Linux platform.
///
/// [accountName] selects a separate libsecret keyring entry (JSON blob) so
/// multiple logical stores can coexist in one app.
class LinuxOptions extends Options {
  /// Creates an instance of [LinuxOptions].
  const LinuxOptions({
    this.accountName = LinuxOptions.defaultAccountName,
  });

  /// Default service namespace (matches [AppleOptions.defaultAccountName]).
  static const defaultAccountName = 'flutter_secure_storage_service';

  /// A predefined [LinuxOptions] instance with default settings.
  static const LinuxOptions defaultOptions = LinuxOptions();

  /// Logical namespace stored as a separate libsecret password.
  final String accountName;

  @override
  Map<String, String> toMap() => <String, String>{
        'accountName': accountName,
      };

  /// Creates a copy with optional overrides.
  LinuxOptions copyWith({String? accountName}) => LinuxOptions(
        accountName: accountName ?? this.accountName,
      );
}
