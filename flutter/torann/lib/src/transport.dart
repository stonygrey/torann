// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

part of 'torann_library.dart';

/// Post-handshake transport state held by the host. A lost or reordered message
/// desynchronizes the nonces, and the application discards the transport after a
/// decrypt failure.
final class Transport {
  Transport._fromHandle(int handle)
    : _native = NativeHandle(
        handle,
        'Transport',
        (h) => hostApi.closeTransport(h),
      );

  /// Size in bytes of the AEAD authentication tag appended to every transport message.
  static const int tagSize = 16;

  final NativeHandle _native;

  /// Encrypts a payload of at most 65519 bytes. Returns ciphertext followed by the tag.
  Future<Uint8List> writeMessage(Uint8List payload) =>
      hostCall(() => hostApi.transportWrite(_native.require(), payload));

  /// Decrypts and authenticates a message. Returns the payload.
  Future<Uint8List> readMessage(Uint8List message) =>
      hostCall(() => hostApi.transportRead(_native.require(), message));

  /// Rekeys the outgoing CipherState (Noise §11.3). Does not reset the nonce.
  Future<void> rekeySend() =>
      hostCall(() => hostApi.transportRekeySend(_native.require()));

  /// Rekeys the incoming CipherState (Noise §11.3). Does not reset the nonce.
  Future<void> rekeyReceive() =>
      hostCall(() => hostApi.transportRekeyReceive(_native.require()));

  /// Sets the outgoing nonce. For out-of-order transport (Noise §11.4) only. Dart's
  /// `int` is signed, so the range is 0 to 2^63 − 1.
  Future<void> setSendNonce(int nonce) => hostCall(
    () => hostApi.transportSetSendNonce(_native.require(), _checkNonce(nonce)),
  );

  /// Sets the incoming nonce. For out-of-order transport (Noise §11.4) only.
  Future<void> setReceiveNonce(int nonce) => hostCall(
    () =>
        hostApi.transportSetReceiveNonce(_native.require(), _checkNonce(nonce)),
  );

  /// Closes both cipher states on the host. Every operation afterwards raises
  /// [ClosedException]. Calling it twice has no further effect.
  Future<void> close() => _native.close();

  static int _checkNonce(int nonce) {
    if (nonce < 0) {
      throw const InvalidArgumentException('The nonce must not be negative.');
    }
    return nonce;
  }
}
