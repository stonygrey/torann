// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

part of 'torann_library.dart';

/// A DH key pair held by the host. Create one with [NoiseProtocol.generateKeyPair] or
/// [NoiseProtocol.createKeyPair]. The public key is cached here when the key pair is
/// created; the private key is fetched from the host on each call.
final class KeyPair {
  KeyPair._fromMessage(KeyPairMessage message)
    : _publicKey = Uint8List.fromList(message.publicKey),
      _native = NativeHandle(
        message.handle,
        'KeyPair',
        (h) => hostApi.closeKeyPair(h),
      );

  final Uint8List _publicKey;
  final NativeHandle _native;

  /// A copy of the public key. Raises [ClosedException] after [close].
  Uint8List get publicKey {
    _native.require();
    return Uint8List.fromList(_publicKey);
  }

  /// A copy of the private key. Raises [ClosedException] after [close].
  Future<Uint8List> privateKey() =>
      hostCall(() => hostApi.keyPairPrivateKey(_native.require()));

  /// Zeros the private key on the host and releases the native object. Calling it
  /// twice has no further effect.
  Future<void> close() => _native.close();
}
