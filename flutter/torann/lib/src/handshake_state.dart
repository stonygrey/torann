// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

part of 'torann_library.dart';

/// The result of [HandshakeState.writeMessage]. [handshakeHash] and [transport] are
/// present on the final message of the pattern only.
final class HandshakeWriteResult {
  const HandshakeWriteResult._({
    required this.message,
    this.handshakeHash,
    this.transport,
  });
  final Uint8List message;
  final Uint8List? handshakeHash;
  final Transport? transport;
}

/// The result of [HandshakeState.readMessage]. [handshakeHash] and [transport] are
/// present on the final message of the pattern only.
final class HandshakeReadResult {
  const HandshakeReadResult._({
    required this.payload,
    this.handshakeHash,
    this.transport,
  });
  final Uint8List payload;
  final Uint8List? handshakeHash;
  final Transport? transport;
}

/// HandshakeState per Noise §5.3, held by the host. Call [writeMessage] and
/// [readMessage] alternately; the final message returns a [Transport]. A decrypt or DH
/// failure after a message pattern is consumed is terminal: the handshake refuses
/// further use and must be discarded.
final class HandshakeState {
  HandshakeState._fromHandle(int handle)
    : _native = NativeHandle(
        handle,
        'HandshakeState',
        (h) => hostApi.closeHandshake(h),
      );

  final NativeHandle _native;

  /// Writes the next handshake message.
  Future<HandshakeWriteResult> writeMessage([Uint8List? payload]) async {
    final result = await hostCall(
      () => hostApi.handshakeWrite(_native.require(), payload ?? Uint8List(0)),
    );
    final transportHandle = result.transportHandle;
    return HandshakeWriteResult._(
      message: result.message,
      handshakeHash: result.handshakeHash,
      transport: transportHandle == null
          ? null
          : Transport._fromHandle(transportHandle),
    );
  }

  /// Reads the next handshake message from the peer.
  Future<HandshakeReadResult> readMessage(Uint8List message) async {
    final result = await hostCall(
      () => hostApi.handshakeRead(_native.require(), message),
    );
    final transportHandle = result.transportHandle;
    return HandshakeReadResult._(
      payload: result.payload,
      handshakeHash: result.handshakeHash,
      transport: transportHandle == null
          ? null
          : Transport._fromHandle(transportHandle),
    );
  }

  /// The peer's static public key once known: at once when it was passed to
  /// `createHandshake`, after the message that carried it otherwise. Null after a
  /// terminal failure. Raises [ClosedException] after [close].
  Future<Uint8List?> remoteStaticPublicKey() =>
      hostCall(() => hostApi.handshakeRemoteStaticPublicKey(_native.require()));

  /// Zeros all key material on the host. Every operation afterwards raises
  /// [ClosedException]. Calling it twice has no further effect.
  Future<void> close() => _native.close();
}

/// Test-only: the vector suites prescribe each party's ephemeral private key. Exported
/// from `package:torann/testing.dart` only; `package:torann/torann.dart` hides it, and
/// application code must not import `testing.dart`.
Future<void> setFixedEphemeral(
  HandshakeState handshake,
  Uint8List privateKey,
) => hostCall(
  () => hostApi.setFixedEphemeral(handshake._native.require(), privateKey),
);
