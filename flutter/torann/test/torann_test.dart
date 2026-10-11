// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// Unit tests of the Dart API layer against a fake host API. They check the mapping of
// Pigeon error codes to typed exceptions, the closed-state tracking that stops calls
// before they reach the host, and the plumbing of handles and results. The
// cryptography is tested natively and through the example app's integration tests.

import 'dart:typed_data';

import 'package:flutter/services.dart' show PlatformException;
import 'package:flutter_test/flutter_test.dart';
import 'package:torann/src/host.dart';
import 'package:torann/src/messages.g.dart';
import 'package:torann/torann.dart';

/// A host that records calls and returns canned values. It subclasses the generated
/// class and overrides every method, so no platform channel is ever touched.
class FakeHost extends TorannHostApi {
  final calls = <String>[];
  int nextHandle = 100;
  final closed = <int>[];
  bool channelGone = false;

  Never _fail(String code, String message) =>
      throw PlatformException(code: code, message: message);

  @override
  Future<void> parseProtocol(String name) async {
    calls.add('parseProtocol $name');
    if (!name.startsWith('Noise_')) {
      _fail(
        'invalidProtocolName',
        "'$name' is not a valid Noise protocol name.",
      );
    }
    if (name.contains('448')) {
      _fail('unsupportedFunction', "DH function '448' is not supported.");
    }
  }

  @override
  Future<KeyPairMessage> generateKeyPair(String protocol) async {
    calls.add('generateKeyPair $protocol');
    return KeyPairMessage(
      handle: nextHandle++,
      publicKey: Uint8List.fromList(List.filled(32, 7)),
    );
  }

  @override
  Future<KeyPairMessage> createKeyPair(
    String protocol,
    Uint8List privateKey,
  ) async {
    calls.add('createKeyPair $protocol ${privateKey.length}');
    if (privateKey.length != 32) {
      _fail('invalidArgument', 'The private key must be 32 bytes.');
    }
    return KeyPairMessage(
      handle: nextHandle++,
      publicKey: Uint8List.fromList(List.filled(32, 9)),
    );
  }

  @override
  Future<Uint8List> keyPairPrivateKey(int keyPair) async =>
      Uint8List.fromList(List.filled(32, 1));

  @override
  Future<void> closeKeyPair(int keyPair) async => closed.add(keyPair);

  @override
  Future<int> createHandshake(
    String protocol,
    bool initiator,
    Uint8List prologue,
    int? localStatic,
    Uint8List? remoteStatic,
    List<Uint8List> psks,
  ) async {
    calls.add(
      'createHandshake $protocol $initiator ${prologue.length} $localStatic ${remoteStatic?.length} ${psks.length}',
    );
    return nextHandle++;
  }

  @override
  Future<HandshakeWriteMessage> handshakeWrite(
    int handshake,
    Uint8List payload,
  ) async {
    calls.add('handshakeWrite $handshake ${payload.length}');
    return HandshakeWriteMessage(
      message: Uint8List(48),
      handshakeHash: Uint8List(32),
      transportHandle: nextHandle++,
    );
  }

  @override
  Future<HandshakeReadMessage> handshakeRead(
    int handshake,
    Uint8List message,
  ) async {
    calls.add('handshakeRead $handshake ${message.length}');
    _fail('authenticationFailed', 'The handshake message is truncated.');
  }

  @override
  Future<Uint8List?> handshakeRemoteStaticPublicKey(int handshake) async =>
      null;

  @override
  Future<void> closeHandshake(int handshake) async => closed.add(handshake);

  @override
  Future<Uint8List> transportWrite(int transport, Uint8List payload) async =>
      Uint8List(payload.length + 16);

  @override
  Future<Uint8List> transportRead(int transport, Uint8List message) async =>
      Uint8List(message.length - 16);

  @override
  Future<void> transportRekeySend(int transport) async {
    if (channelGone) {
      _fail('channel-error', 'Unable to establish connection on channel.');
    }
    calls.add('rekeySend $transport');
  }

  @override
  Future<void> transportRekeyReceive(int transport) async => _fail(
    'invalidState',
    "A one-way pattern's initiator cannot receive transport messages.",
  );

  @override
  Future<void> transportSetSendNonce(int transport, int nonce) async =>
      calls.add('setSendNonce $transport $nonce');

  @override
  Future<void> transportSetReceiveNonce(int transport, int nonce) async {}

  bool failNextClose = false;

  @override
  Future<void> closeTransport(int transport) async {
    if (failNextClose) {
      failNextClose = false;
      _fail('channel-error', 'Unable to establish connection on channel.');
    }
    closed.add(transport);
  }

  @override
  Future<void> setFixedEphemeral(int handshake, Uint8List privateKey) async =>
      calls.add('setFixedEphemeral $handshake');
}

void main() {
  late FakeHost host;

  setUp(() {
    host = FakeHost();
    setHostApiForTesting(host);
  });

  tearDown(() => setHostApiForTesting(null));

  test(
    'parse keeps the name and maps parse errors to typed exceptions',
    () async {
      final protocol = await NoiseProtocol.parse(
        'Noise_XX_25519_ChaChaPoly_SHA256',
      );
      expect(protocol.name, 'Noise_XX_25519_ChaChaPoly_SHA256');
      expect(NoiseProtocol.maxMessageLength, 65535);
      await expectLater(
        NoiseProtocol.parse('Noise_XX_448_ChaChaPoly_SHA256'),
        throwsA(
          isA<UnsupportedFunctionException>().having(
            (e) => e.message,
            'message',
            "DH function '448' is not supported.",
          ),
        ),
      );
      await expectLater(
        NoiseProtocol.parse('nonsense'),
        throwsA(isA<InvalidProtocolNameException>()),
      );
    },
  );

  test(
    'key pairs cache the public key, fetch the private key, and track close',
    () async {
      final protocol = await NoiseProtocol.parse(
        'Noise_XX_25519_ChaChaPoly_SHA256',
      );
      final keys = await protocol.generateKeyPair();
      expect(keys.publicKey, List.filled(32, 7));
      keys.publicKey[0] = 0;
      expect(keys.publicKey[0], 7, reason: 'publicKey returns a copy');
      expect(await keys.privateKey(), List.filled(32, 1));

      await expectLater(
        protocol.createKeyPair(Uint8List(31)),
        throwsA(isA<InvalidArgumentException>()),
      );

      await keys.close();
      await keys.close();
      expect(host.closed, [100], reason: 'closed once on the host');
      expect(() => keys.publicKey, throwsA(isA<ClosedException>()));
      await expectLater(keys.privateKey(), throwsA(isA<ClosedException>()));
      expect(
        host.calls.where((c) => c.startsWith('keyPairPrivateKey')),
        isEmpty,
        reason: 'closed objects never reach the host',
      );
    },
  );

  test(
    'handshakes pass arguments through, wrap results, and map errors',
    () async {
      final protocol = await NoiseProtocol.parse(
        'Noise_XX_25519_ChaChaPoly_SHA256',
      );
      final keys = await protocol.generateKeyPair();
      final handshake = await protocol.createHandshake(
        initiator: true,
        localStatic: keys,
        psks: [Uint8List(32)],
      );
      expect(
        host.calls.last,
        'createHandshake Noise_XX_25519_ChaChaPoly_SHA256 true 0 100 null 1',
      );

      final written = await handshake.writeMessage(Uint8List(5));
      expect(written.message.length, 48);
      expect(written.handshakeHash, isNotNull);
      expect(written.transport, isNotNull);

      await expectLater(
        handshake.readMessage(Uint8List(3)),
        throwsA(isA<AuthenticationFailedException>()),
      );

      final transport = written.transport!;
      expect((await transport.writeMessage(Uint8List(10))).length, 26);
      await transport.rekeySend();
      await expectLater(
        transport.rekeyReceive(),
        throwsA(isA<InvalidStateException>()),
      );
      await expectLater(
        transport.setSendNonce(-1),
        throwsA(isA<InvalidArgumentException>()),
      );
      await transport.setSendNonce(5);
      expect(host.calls.last, 'setSendNonce 102 5');

      await transport.close();
      await expectLater(
        transport.writeMessage(Uint8List(1)),
        throwsA(isA<ClosedException>()),
      );
      await handshake.close();
      await expectLater(
        handshake.writeMessage(),
        throwsA(isA<ClosedException>()),
      );
      expect(host.closed, containsAll([101, 102]));
    },
  );

  test(
    'errors outside the six categories become HostFailureException',
    () async {
      final protocol = await NoiseProtocol.parse(
        'Noise_XX_25519_ChaChaPoly_SHA256',
      );
      final handshake = await protocol.createHandshake(initiator: true);
      final transport = (await handshake.writeMessage()).transport!;
      host.channelGone = true;
      await expectLater(
        transport.rekeySend(),
        throwsA(
          isA<HostFailureException>().having(
            (e) => e.code,
            'code',
            'channel-error',
          ),
        ),
      );
    },
  );

  test('a failed host release leaves the handle open for a retry', () async {
    final protocol = await NoiseProtocol.parse('Noise_XX_25519_ChaChaPoly_SHA256');
    final handshake = await protocol.createHandshake(initiator: true);
    final transport = (await handshake.writeMessage()).transport!;
    final before = host.closed.length;
    host.failNextClose = true;
    await expectLater(transport.close(), throwsA(isA<HostFailureException>()));
    expect(host.closed, hasLength(before), reason: 'the host never released it');
    await transport.close();
    expect(host.closed, hasLength(before + 1), reason: 'the retry released it');
    await expectLater(transport.writeMessage(Uint8List(1)), throwsA(isA<ClosedException>()));
  });

  test('a closed key pair cannot be passed to createHandshake', () async {
    final protocol = await NoiseProtocol.parse(
      'Noise_XX_25519_ChaChaPoly_SHA256',
    );
    final keys = await protocol.generateKeyPair();
    await keys.close();
    await expectLater(
      protocol.createHandshake(initiator: true, localStatic: keys),
      throwsA(isA<ClosedException>()),
    );
  });
}
