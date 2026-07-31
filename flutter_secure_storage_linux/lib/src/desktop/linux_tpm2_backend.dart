import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_secure_storage_platform_interface/desktop_secure_storage.dart';
import 'package:path/path.dart' as p;

/// Linux TPM2 backend using optional `tpm2-tools` CLI (soft dependency).
///
/// When tools / TPM device are unavailable, [available] is false and callers
/// must fail closed for `hardwareBackedRequired`.
class LinuxTpm2Backend {
  LinuxTpm2Backend({
    Directory? storageRoot,
    bool? availableOverride,
    Future<ProcessResult> Function(String exe, List<String> args)? run,
  })  : _storageRoot = storageRoot,
        _availableOverride = availableOverride,
        _run = run ?? ((exe, args) => Process.run(exe, args));

  final Directory? _storageRoot;
  final bool? _availableOverride;
  final Future<ProcessResult> Function(String exe, List<String> args) _run;

  Future<Directory> _root() async {
    if (_storageRoot != null) {
      await _storageRoot!.create(recursive: true);
      return Directory(p.join(_storageRoot!.path, 'tpm'));
    }
    final xdg = Platform.environment['XDG_DATA_HOME'];
    final home = Platform.environment['HOME'];
    final base = (xdg != null && xdg.isNotEmpty)
        ? xdg
        : (home != null && home.isNotEmpty)
            ? p.join(home, '.local', 'share')
            : Directory.systemTemp.path;
    final dir = Directory(
      p.join(base, 'flutter_secure_storage', 'private_keys', 'tpm'),
    );
    await dir.create(recursive: true);
    return dir;
  }

  Future<bool> available() async {
    if (_availableOverride != null) {
      return _availableOverride!;
    }
    try {
      final which = await _run('which', ['tpm2_createprimary']);
      if (which.exitCode != 0) {
        return false;
      }
      final cap = await _run('tpm2_getcap', ['properties-fixed']);
      return cap.exitCode == 0;
    } catch (_) {
      return false;
    }
  }

  Future<LinuxTpmKey> createEccP256(String keyId) async {
    if (!await available()) {
      throw const DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.hardwareRequiredButUnavailable,
        message: 'TPM2 tools / device unavailable',
        provider: 'tpm2',
      );
    }
    final root = await _root();
    final dir = Directory(
      p.join(root.path, sanitizeKeyIdForFilename(keyId)),
    );
    await dir.create(recursive: true);
    final primaryCtx = p.join(dir.path, 'primary.ctx');
    final keyCtx = p.join(dir.path, 'key.ctx');
    final pub = p.join(dir.path, 'key.pub');
    final priv = p.join(dir.path, 'key.priv');

    Future<void> step(String exe, List<String> args) async {
      final r = await _run(exe, args);
      if (r.exitCode != 0) {
        throw DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.accessDenied,
          message: 'tpm2 command failed: $exe ${args.join(' ')}\n${r.stderr}',
          provider: 'tpm2',
        );
      }
    }

    await step('tpm2_createprimary', [
      '-C',
      'o',
      '-g',
      'sha256',
      '-G',
      'ecc:nist_p256',
      '-c',
      primaryCtx,
    ]);
    await step('tpm2_create', [
      '-C',
      primaryCtx,
      '-g',
      'sha256',
      '-G',
      'ecc:nist_p256',
      '-u',
      pub,
      '-r',
      priv,
    ]);
    await step('tpm2_load', [
      '-C',
      primaryCtx,
      '-u',
      pub,
      '-r',
      priv,
      '-c',
      keyCtx,
    ]);

    // Export public as TPM2B_PUBLIC; also try PEM for SPKI via tpm2_readpublic.
    final pemPath = p.join(dir.path, 'key.pem');
    await step('tpm2_readpublic', ['-c', keyCtx, '-f', 'pem', '-o', pemPath]);
    final pem = await File(pemPath).readAsString();
    final spki = _pemToDer(pem, 'PUBLIC KEY');

    return LinuxTpmKey(
      keyId: keyId,
      directory: dir.path,
      publicKeySpkiDer: spki,
    );
  }

  Future<Uint8List> sign(String keyId, Uint8List data) async {
    final root = await _root();
    final dir = Directory(
      p.join(root.path, sanitizeKeyIdForFilename(keyId)),
    );
    final keyCtx = p.join(dir.path, 'key.ctx');
    if (!File(keyCtx).existsSync()) {
      // Reload from pub/priv if context was flushed.
      final primaryCtx = p.join(dir.path, 'primary.ctx');
      final pub = p.join(dir.path, 'key.pub');
      final priv = p.join(dir.path, 'key.priv');
      if (!File(pub).existsSync() || !File(priv).existsSync()) {
        throw const DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.keyNotFound,
          message: 'TPM key material missing',
          provider: 'tpm2',
        );
      }
      var r = await _run('tpm2_createprimary', [
        '-C',
        'o',
        '-g',
        'sha256',
        '-G',
        'ecc:nist_p256',
        '-c',
        primaryCtx,
      ]);
      if (r.exitCode != 0) {
        throw DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.accessDenied,
          message: 'tpm2_createprimary failed: ${r.stderr}',
          provider: 'tpm2',
        );
      }
      r = await _run('tpm2_load', [
        '-C',
        primaryCtx,
        '-u',
        pub,
        '-r',
        priv,
        '-c',
        keyCtx,
      ]);
      if (r.exitCode != 0) {
        throw DesktopSecureStorageException(
          code: DesktopSecureStorageErrorCode.accessDenied,
          message: 'tpm2_load failed: ${r.stderr}',
          provider: 'tpm2',
        );
      }
    }

    final msg = p.join(dir.path, 'msg.bin');
    final sig = p.join(dir.path, 'sig.bin');
    await File(msg).writeAsBytes(data, flush: true);
    final r = await _run('tpm2_sign', [
      '-c',
      keyCtx,
      '-g',
      'sha256',
      '-o',
      sig,
      msg,
    ]);
    if (r.exitCode != 0) {
      throw DesktopSecureStorageException(
        code: DesktopSecureStorageErrorCode.accessDenied,
        message: 'tpm2_sign failed: ${r.stderr}',
        provider: 'tpm2',
      );
    }
    return Uint8List.fromList(await File(sig).readAsBytes());
  }

  Future<void> delete(String keyId) async {
    final root = await _root();
    final dir = Directory(
      p.join(root.path, sanitizeKeyIdForFilename(keyId)),
    );
    if (dir.existsSync()) {
      await dir.delete(recursive: true);
    }
  }

  Uint8List _pemToDer(String pem, String label) {
    final lines = pem
        .split('\n')
        .where((l) => !l.startsWith('-----'))
        .map((l) => l.trim())
        .where((l) => l.isNotEmpty)
        .join();
    return Uint8List.fromList(base64.decode(lines));
  }
}

/// Handle for a TPM-resident key created via tpm2-tools.
class LinuxTpmKey {
  LinuxTpmKey({
    required this.keyId,
    required this.directory,
    required this.publicKeySpkiDer,
  });

  final String keyId;
  final String directory;
  final Uint8List publicKeySpkiDer;
}
