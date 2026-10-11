// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

part of 'torann_library.dart';

/// A parsed Noise protocol name such as `Noise_XX_25519_ChaChaPoly_SHA256`, and the
/// factory for key pairs and handshakes. The supported functions depend on the host:
/// Android (Kotlin) supports `25519`, `448`, `ChaChaPoly`, `AESGCM`, `SHA256`, `SHA512`,
/// `BLAKE2s`, and `BLAKE2b`; iOS (Swift) supports `25519`, `ChaChaPoly`, `AESGCM`,
/// `SHA256`, and `SHA512`. An application that runs on both platforms uses `25519` with
/// `SHA256` or `SHA512`.
final class NoiseProtocol {
  NoiseProtocol._(this.name);

  /// Maximum length in bytes of a Noise handshake or transport message (Noise §3).
  static const int maxMessageLength = 65535;

  /// The full protocol name, exactly as parsed.
  final String name;

  /// Parses a protocol name. Raises [InvalidProtocolNameException] for a malformed
  /// name and [UnsupportedFunctionException] for a function this platform lacks.
  static Future<NoiseProtocol> parse(String name) async {
    await hostCall(() => hostApi.parseProtocol(name));
    return NoiseProtocol._(name);
  }

  /// Generates a fresh static key pair for this protocol's DH function.
  Future<KeyPair> generateKeyPair() async {
    final message = await hostCall(() => hostApi.generateKeyPair(name));
    return KeyPair._fromMessage(message);
  }

  /// Reconstructs a key pair from a stored private key.
  Future<KeyPair> createKeyPair(Uint8List privateKey) async {
    final message = await hostCall(
      () => hostApi.createKeyPair(name, privateKey),
    );
    return KeyPair._fromMessage(message);
  }

  /// Creates a handshake. [initiator] is true for the party that sends the first
  /// message. [prologue] is authenticated but not transmitted. [localStatic] is
  /// required when the pattern sends or pre-shares this party's static key, and
  /// [remoteStatic] when it pre-shares the peer's. [psks] holds one 32-byte key per
  /// psk modifier, consumed in the order the `psk` tokens occur in the pattern. The
  /// host copies every argument. A closed [localStatic] raises [ClosedException] before
  /// the host is called.
  Future<HandshakeState> createHandshake({
    required bool initiator,
    Uint8List? prologue,
    KeyPair? localStatic,
    Uint8List? remoteStatic,
    List<Uint8List>? psks,
  }) async {
    final localHandle = localStatic?._native.require();
    final handle = await hostCall(
      () => hostApi.createHandshake(
        name,
        initiator,
        prologue ?? Uint8List(0),
        localHandle,
        remoteStatic,
        psks ?? const [],
      ),
    );
    return HandshakeState._fromHandle(handle);
  }
}
