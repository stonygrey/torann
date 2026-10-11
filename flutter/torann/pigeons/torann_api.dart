// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// The Pigeon definition of the host API. Regenerate the Dart, Swift, and Kotlin
// files with `dart run pigeon --input pigeons/torann_api.dart` from flutter/torann.
//
// The host keeps a table of open key pair, handshake, and transport objects and hands
// Dart an integer handle for each. A protocol has no state beyond its name, so every
// call that needs one takes the name and the host parses it again. Errors cross the
// boundary as a PlatformException whose code is the shared error category.

import 'package:pigeon/pigeon.dart';

@ConfigurePigeon(
  PigeonOptions(
    dartOut: 'lib/src/messages.g.dart',
    swiftOut: 'ios/torann/Sources/torann/Messages.g.swift',
    kotlinOut: 'android/src/main/kotlin/com/stonygrey/torann/Messages.g.kt',
    kotlinOptions: KotlinOptions(package: 'com.stonygrey.torann'),
    dartPackageName: 'torann',
    copyrightHeader: 'pigeons/copyright.txt',
  ),
)
class KeyPairMessage {
  KeyPairMessage({required this.handle, required this.publicKey});
  int handle;
  Uint8List publicKey;
}

class HandshakeWriteMessage {
  HandshakeWriteMessage({required this.message, this.handshakeHash, this.transportHandle});
  Uint8List message;
  Uint8List? handshakeHash;
  int? transportHandle;
}

class HandshakeReadMessage {
  HandshakeReadMessage({required this.payload, this.handshakeHash, this.transportHandle});
  Uint8List payload;
  Uint8List? handshakeHash;
  int? transportHandle;
}

/// Every host call runs on a serial background queue rather than the platform thread,
/// so a handshake step does not block the UI. Pigeon takes the annotation per method.
/// The library objects carry their own locks.
@HostApi()
abstract class TorannHostApi {
  /// Exists to raise the parse errors; Dart keeps only the name.
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  void parseProtocol(String name);

  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  KeyPairMessage generateKeyPair(String protocol);
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  KeyPairMessage createKeyPair(String protocol, Uint8List privateKey);
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  Uint8List keyPairPrivateKey(int keyPair);
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  void closeKeyPair(int keyPair);

  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  int createHandshake(
    String protocol,
    bool initiator,
    Uint8List prologue,
    int? localStatic,
    Uint8List? remoteStatic,
    List<Uint8List> psks,
  );
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  HandshakeWriteMessage handshakeWrite(int handshake, Uint8List payload);
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  HandshakeReadMessage handshakeRead(int handshake, Uint8List message);
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  Uint8List? handshakeRemoteStaticPublicKey(int handshake);
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  void closeHandshake(int handshake);

  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  Uint8List transportWrite(int transport, Uint8List payload);
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  Uint8List transportRead(int transport, Uint8List message);
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  void transportRekeySend(int transport);
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  void transportRekeyReceive(int transport);
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  void transportSetSendNonce(int transport, int nonce);
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  void transportSetReceiveNonce(int transport, int nonce);
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  void closeTransport(int transport);

  /// Test-only (package:torann/testing.dart): the vectors prescribe each party's
  /// ephemeral private key.
  @TaskQueue(type: TaskQueueType.serialBackgroundThread)
  void setFixedEphemeral(int handshake, Uint8List privateKey);
}
