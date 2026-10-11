// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import 'dart:async';

import 'package:flutter/foundation.dart' show kDebugMode, debugPrint;
import 'package:flutter/services.dart' show PlatformException;

import 'messages.g.dart';
import 'torann_exception.dart';

TorannHostApi? _override;

/// The host API every Torann object calls. The Dart unit tests replace it with a
/// fake through [setHostApiForTesting]; application code never touches it.
TorannHostApi get hostApi => _override ??= TorannHostApi();

/// Replaces the host API. For the package's own unit tests only.
void setHostApiForTesting(TorannHostApi? api) {
  _override = api;
}

/// Runs one host call and converts a [PlatformException] into the typed exception.
Future<T> hostCall<T>(Future<T> Function() call) async {
  try {
    return await call();
  } on PlatformException catch (e) {
    throw torannExceptionFromCode(e.code, e.message);
  }
}

/// A native object the host holds on Dart's behalf, named by an integer handle.
/// [close] releases it exactly once; the finalizer releases it if the owner forgot.
final class NativeHandle {
  NativeHandle(this.handle, this.kind, this._release) {
    _finalizer.attach(this, _Release(handle, kind, _release), detach: this);
  }

  final int handle;
  final String kind;
  final Future<void> Function(int handle) _release;
  bool _closed = false;

  bool get isClosed => _closed;

  /// Raises [ClosedException] after [close].
  int require() {
    if (_closed) {
      throw const ClosedException();
    }
    return handle;
  }

  Future<void> close() async {
    if (_closed) {
      return;
    }
    _closed = true;
    try {
      await hostCall(() => _release(handle));
    } catch (_) {
      // The host still holds the object: leave the handle open so that a later
      // close() or the finalizer can release it.
      _closed = false;
      rethrow;
    }
    _finalizer.detach(this);
  }

  static final Finalizer<_Release> _finalizer = Finalizer((release) {
    // The only output the Dart layer produces; it must not carry key material.
    if (kDebugMode) {
      debugPrint(
        'torann: ${release.kind} with handle ${release.handle} was not closed; '
        'the finalizer released it.',
      );
    }
    unawaited(release.release(release.handle).catchError((Object _) {}));
  });
}

final class _Release {
  const _Release(this.handle, this.kind, this.release);
  final int handle;
  final String kind;
  final Future<void> Function(int handle) release;
}
