part of '../flutter_secure_storage.dart';

/// Specific options for Windows platform.
class WindowsOptions extends Options {
  /// * If `useBackwardCompatibility` is set to true, trying to read from values
  ///   which were written by previous versions. In addition, when reading or
  ///   writing from previous version's storage, read values will be migrated to
  ///   new storage automatically. This may introduces some performance hit and
  ///   might cause error for some kinds of keys.
  ///   Default is `false`.
  ///   You must set this value to `false` if you could use:
  ///   * Keys containing `"`, `<`, `>`, `|`, `:`, `*`, `?`, `/`, `\`,
  ///     or any of ASCII control charactors.
  ///   * Keys containing `/../`, `\..\`, or their combinations.
  ///   * Long key string (precise size is depends on your app's product name,
  ///     company name, and account name who executes your app).
  ///
  /// You can migrate all old data with this options as following:
  /// ```dart
  /// await FlutterSecureStorage().readAll(
  ///     const WindowsOptions(useBackwardCompatibility: true),
  /// );
  /// ```
  ///
  /// * [accountName] selects a separate DPAPI-encrypted JSON file under the app
  ///   support directory (default [WindowsOptions.defaultAccountName]).
  ///
  /// * [useLocalMachine] uses `CRYPTPROTECT_LOCAL_MACHINE` so secrets are tied
  ///   to the machine (readable by any process running as the same Windows user
  ///   context that created them, and by elevated services). Default is `false`
  ///   (user-scoped DPAPI). Only enable for Windows services or shared-machine
  ///   scenarios; see [DESKTOP_STORAGE.md](https://github.com/fl-start/flutter_secure_storage/blob/develop/DESKTOP_STORAGE.md).
  const WindowsOptions({
    bool useBackwardCompatibility = false,
    bool useLocalMachine = false,
    this.accountName = WindowsOptions.defaultAccountName,
  })  : _useBackwardCompatibility = useBackwardCompatibility,
        _useLocalMachine = useLocalMachine;

  /// Default namespace for the encrypted JSON file name.
  static const defaultAccountName = 'flutter_secure_storage_service';

  /// A predefined [WindowsOptions] instance with default settings.
  static const WindowsOptions defaultOptions = WindowsOptions();

  final bool _useBackwardCompatibility;
  final bool _useLocalMachine;

  /// Logical namespace; maps to `flutter_secure_storage_<accountName>.dat`.
  final String accountName;

  @override
  Map<String, String> toMap() => <String, String>{
        'useBackwardCompatibility': _useBackwardCompatibility.toString(),
        'useLocalMachine': _useLocalMachine.toString(),
        'accountName': accountName,
      };

  /// Creates a new instance of [WindowsOptions] by copying the current instance
  /// and replacing specified properties with new values.
  WindowsOptions copyWith({
    bool? useBackwardCompatibility,
    bool? useLocalMachine,
    String? accountName,
  }) =>
      WindowsOptions(
        useBackwardCompatibility:
            useBackwardCompatibility ?? _useBackwardCompatibility,
        useLocalMachine: useLocalMachine ?? _useLocalMachine,
        accountName: accountName ?? this.accountName,
      );
}
