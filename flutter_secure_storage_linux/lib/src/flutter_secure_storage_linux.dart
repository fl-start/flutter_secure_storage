import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';

import 'desktop/linux_desktop_key_manager.dart';

/// Linux plugin Dart registration (federated `dartPluginClass`).
class FlutterSecureStorageLinux {
  /// Registers the Linux [DesktopPrivateKeyManager].
  ///
  /// Key-value storage continues to use the default method-channel
  /// implementation against the native Linux plugin.
  static void registerWith() {
    DesktopPrivateKeyManager.instance = LinuxDesktopKeyManager();
  }
}
