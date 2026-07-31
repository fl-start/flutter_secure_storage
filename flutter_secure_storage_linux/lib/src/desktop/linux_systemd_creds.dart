import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';

/// Optional systemd-creds encrypt/decrypt wrap (soft dependency).
class LinuxSystemdCreds {
  LinuxSystemdCreds({
    bool? availableOverride,
    Future<ProcessResult> Function(
      String executable,
      List<String> arguments, {
      String? stdin,
    })? run,
  })  : _availableOverride = availableOverride,
        _run = run ??
            ((exe, args, {stdin}) => Process.run(
                  exe,
                  args,
                  runInShell: false,
                ));

  final bool? _availableOverride;
  final Future<ProcessResult> Function(
    String executable,
    List<String> arguments, {
    String? stdin,
  }) _run;

  static const tokenPrefix = 'sd1:';

  Future<bool> available() async {
    if (_availableOverride != null) {
      return _availableOverride!;
    }
    try {
      final which = await Process.run('which', ['systemd-creds']);
      if (which.exitCode != 0) {
        return false;
      }
      // Prefer hosts that actually run systemd.
      final show = await Process.run('systemctl', ['is-system-running']);
      final out = '${show.stdout}'.trim();
      return show.exitCode == 0 ||
          out == 'running' ||
          out == 'degraded' ||
          out == 'offline';
    } catch (_) {
      return false;
    }
  }

  /// Encrypt [plain] under a named credential; returns token `sd1:` + base64.
  Future<Uint8List> wrap(String keyId, Uint8List plain) async {
    if (!await available()) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.providerUnavailable,
        message: 'systemd-creds unavailable',
        provider: 'systemd_creds',
      );
    }
    final name = 'fss-${sanitizeKeyIdForFilename(keyId)}';
    final proc = await Process.start('systemd-creds', [
      'encrypt',
      '--name=$name',
      '-',
      '-',
    ]);
    proc.stdin.add(plain);
    await proc.stdin.close();
    final stdout = await proc.stdout.fold<List<int>>(
      <int>[],
      (prev, el) => prev..addAll(el),
    );
    final stderr = await proc.stderr.transform(utf8.decoder).join();
    final code = await proc.exitCode;
    if (code != 0) {
      throw DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.accessDenied,
        message: 'systemd-creds encrypt failed: $stderr',
        provider: 'systemd_creds',
      );
    }
    final token = tokenPrefix + base64Encode(stdout);
    return Uint8List.fromList(utf8.encode(token));
  }

  Future<Uint8List> unwrap(Uint8List token) async {
    final text = utf8.decode(token);
    if (!text.startsWith(tokenPrefix)) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.corruptRecord,
        message: 'not a systemd-creds wrap token',
        provider: 'systemd_creds',
      );
    }
    final blob = base64Decode(text.substring(tokenPrefix.length));
    final proc = await Process.start('systemd-creds', [
      'decrypt',
      '-',
      '-',
    ]);
    proc.stdin.add(blob);
    await proc.stdin.close();
    final stdout = await proc.stdout.fold<List<int>>(
      <int>[],
      (prev, el) => prev..addAll(el),
    );
    final stderr = await proc.stderr.transform(utf8.decoder).join();
    final code = await proc.exitCode;
    if (code != 0) {
      throw DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.keyUnwrapFailed,
        message: 'systemd-creds decrypt failed: $stderr',
        provider: 'systemd_creds',
      );
    }
    return Uint8List.fromList(stdout);
  }
}
