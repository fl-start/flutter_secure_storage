import 'dart:async';

import 'support/native_desktop_backend.dart';

Future<void> testExecutable(FutureOr<void> Function() testMain) async {
  NativeDesktopBackend.install();
  await testMain();
}
