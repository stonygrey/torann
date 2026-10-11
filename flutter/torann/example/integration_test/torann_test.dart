// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// Runs the shared vectors through the plugin with their fixed keys, plus
// random-key handshakes through the public API. The vector files are assets copied by
// lib/sync-flutter-sources. Run with:
//   cd flutter/torann/example && flutter test integration_test -d <device>

import 'dart:convert';
import 'dart:io' show Platform;
import 'dart:math';
import 'dart:typed_data';

import 'package:flutter/services.dart' show rootBundle;
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:torann/testing.dart';
import 'package:torann/torann.dart';

Uint8List hex(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String toHex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  // Android (Kotlin) supports every function; iOS (Swift) supports the 25519/SHA-2 subset.
  final full = Platform.isAndroid;

  testWidgets('cacophony vectors', (_) async {
    await runFile(
      'cacophony.txt',
      expectedRun: full ? 944 : 236,
      expectedSkipped: full ? 0 : 708,
    );
  });

  testWidgets('snow vectors', (_) async {
    await runFile(
      'snow.txt',
      expectedRun: full ? 408 : 204,
      expectedSkipped: full ? 0 : 204,
    );
  });

  testWidgets('random-key handshakes and transport round trips', (_) async {
    final names = [
      'Noise_NN_25519_ChaChaPoly_SHA256',
      'Noise_XX_25519_ChaChaPoly_SHA256',
      'Noise_IK_25519_AESGCM_SHA512',
      'Noise_XXpsk3_25519_ChaChaPoly_SHA256',
      if (full) 'Noise_XX_448_ChaChaPoly_BLAKE2s',
    ];
    final random = Random.secure();
    Uint8List randomBytes(int n) =>
        Uint8List.fromList(List.generate(n, (_) => random.nextInt(256)));

    for (final name in names) {
      final protocol = await NoiseProtocol.parse(name);
      final initStatic = await protocol.generateKeyPair();
      final respStatic = await protocol.generateKeyPair();
      final psks = name.contains('psk') ? [randomBytes(32)] : <Uint8List>[];
      final initiator = await protocol.createHandshake(
        initiator: true,
        localStatic: initStatic,
        remoteStatic: name.contains('_IK') ? respStatic.publicKey : null,
        psks: psks,
      );
      final responder = await protocol.createHandshake(
        initiator: false,
        localStatic: respStatic,
        psks: psks,
      );

      HandshakeState writer = initiator, reader = responder;
      Transport? initTransport, respTransport;
      try {
        while (initTransport == null) {
          final written = await writer.writeMessage(utf8.encode('ping'));
          final read = await reader.readMessage(written.message);
          expect(utf8.decode(read.payload), 'ping', reason: name);
          if (written.transport != null) {
            expect(
              toHex(read.handshakeHash!),
              toHex(written.handshakeHash!),
              reason: name,
            );
            initTransport = identical(writer, initiator)
                ? written.transport
                : read.transport;
            respTransport = identical(writer, initiator)
                ? read.transport
                : written.transport;
          }
          (writer, reader) = (reader, writer);
        }

        if (!name.contains('_NN')) {
          expect(
            toHex((await initiator.remoteStaticPublicKey())!),
            toHex(respStatic.publicKey),
            reason: name,
          );
        }
        final data = randomBytes(1024);
        expect(
          toHex(
            await respTransport!.readMessage(
              await initTransport.writeMessage(data),
            ),
          ),
          toHex(data),
          reason: name,
        );
        await initTransport.rekeySend();
        await respTransport.rekeyReceive();
        expect(
          toHex(
            await respTransport.readMessage(
              await initTransport.writeMessage(data),
            ),
          ),
          toHex(data),
          reason: name,
        );

        // Copy before mutating: a Uint8List returned over the platform channel is a view.
        final tampered = Uint8List.fromList(
          await initTransport.writeMessage(data),
        );
        tampered[0] ^= 0xFF;
        await expectLater(
          respTransport.readMessage(tampered),
          throwsA(isA<AuthenticationFailedException>()),
          reason: name,
        );

        await initTransport.close();
        await expectLater(
          initTransport.writeMessage(data),
          throwsA(isA<ClosedException>()),
          reason: name,
        );
      } finally {
        await initTransport?.close();
        await respTransport?.close();
        await initiator.close();
        await responder.close();
        await initStatic.close();
        await respStatic.close();
      }
    }
  });

  testWidgets('key derivation matches RFC 7748 section 6', (_) async {
    final x25519 = await NoiseProtocol.parse(
      'Noise_NN_25519_ChaChaPoly_SHA256',
    );
    final alice = await x25519.createKeyPair(
      hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'),
    );
    expect(
      toHex(alice.publicKey),
      '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a',
    );
    await alice.close();
    if (full) {
      final x448 = await NoiseProtocol.parse('Noise_NN_448_ChaChaPoly_SHA256');
      final bob = await x448.createKeyPair(
        hex(
          '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d',
        ),
      );
      expect(
        toHex(bob.publicKey),
        '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609',
      );
      await bob.close();
    }
  });

  testWidgets('unsupported functions are rejected by name on this platform', (
    _,
  ) async {
    if (full) {
      expect(
        (await NoiseProtocol.parse('Noise_XX_448_ChaChaPoly_BLAKE2b')).name,
        'Noise_XX_448_ChaChaPoly_BLAKE2b',
      );
    } else {
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
    }
    await expectLater(
      NoiseProtocol.parse('Noise_XX_25519_ChaChaPoly'),
      throwsA(isA<InvalidProtocolNameException>()),
    );
  });
}

Future<void> runFile(
  String fileName, {
  required int expectedRun,
  required int expectedSkipped,
}) async {
  final text = await rootBundle.loadString('assets/vectors/$fileName');
  final vectors =
      (jsonDecode(text) as Map<String, dynamic>)['vectors'] as List<dynamic>;
  var run = 0, skipped = 0;
  for (final vector in vectors.cast<Map<String, dynamic>>()) {
    final name = vector['protocol_name'] as String;
    final NoiseProtocol protocol;
    try {
      protocol = await NoiseProtocol.parse(name);
    } on UnsupportedFunctionException {
      skipped++;
      continue;
    }
    try {
      await runVector(protocol, vector);
    } catch (e) {
      fail("Vector '$name' failed: $e");
    }
    run++;
  }
  // ignore: avoid_print
  print('$fileName: ran $run vectors, skipped $skipped unsupported.');
  expect(run, expectedRun, reason: '$fileName run count');
  expect(skipped, expectedSkipped, reason: '$fileName skipped count');
}

Future<void> runVector(
  NoiseProtocol protocol,
  Map<String, dynamic> vector,
) async {
  final name = vector['protocol_name'] as String;
  String? field(String key) => vector[key] as String?;
  List<Uint8List> psks(String key) =>
      ((vector[key] as List<dynamic>?) ?? const [])
          .cast<String>()
          .map(hex)
          .toList();

  final initStatic = field('init_static') == null
      ? null
      : await protocol.createKeyPair(hex(field('init_static')!));
  final respStatic = field('resp_static') == null
      ? null
      : await protocol.createKeyPair(hex(field('resp_static')!));
  final initiator = await protocol.createHandshake(
    initiator: true,
    prologue: hex(field('init_prologue')!),
    localStatic: initStatic,
    remoteStatic: field('init_remote_static') == null
        ? null
        : hex(field('init_remote_static')!),
    psks: psks('init_psks'),
  );
  if (field('init_ephemeral') != null) {
    await setFixedEphemeral(initiator, hex(field('init_ephemeral')!));
  }
  final responder = await protocol.createHandshake(
    initiator: false,
    prologue: hex(field('resp_prologue')!),
    localStatic: respStatic,
    remoteStatic: field('resp_remote_static') == null
        ? null
        : hex(field('resp_remote_static')!),
    psks: psks('resp_psks'),
  );
  if (field('resp_ephemeral') != null) {
    await setFixedEphemeral(responder, hex(field('resp_ephemeral')!));
  }

  Transport? initTransport, respTransport;
  var oneWay = false;
  final messages = (vector['messages'] as List<dynamic>)
      .cast<Map<String, dynamic>>();
  try {
    for (var i = 0; i < messages.length; i++) {
      final payload = hex(messages[i]['payload'] as String);
      final expected = hex(messages[i]['ciphertext'] as String);
      final initiatorSends = oneWay || i.isEven;

      if (initTransport != null && respTransport != null) {
        final writer = initiatorSends ? initTransport : respTransport;
        final reader = initiatorSends ? respTransport : initTransport;
        expect(
          toHex(await writer.writeMessage(payload)),
          toHex(expected),
          reason: '$name transport message $i',
        );
        expect(
          toHex(await reader.readMessage(expected)),
          toHex(payload),
          reason: '$name transport payload $i',
        );
        continue;
      }

      final writer = initiatorSends ? initiator : responder;
      final reader = initiatorSends ? responder : initiator;
      final written = await writer.writeMessage(payload);
      expect(
        toHex(written.message),
        toHex(expected),
        reason: '$name message $i',
      );
      final read = await reader.readMessage(expected);
      expect(toHex(read.payload), toHex(payload), reason: '$name payload $i');

      if (written.transport != null) {
        expect(
          read.transport,
          isNotNull,
          reason: '$name: reader produced no transport',
        );
        initTransport = initiatorSends ? written.transport : read.transport;
        respTransport = initiatorSends ? read.transport : written.transport;
        if (i == 0) {
          oneWay = true;
        }
        expect(
          toHex(read.handshakeHash!),
          toHex(written.handshakeHash!),
          reason: '$name handshake hashes differ',
        );
        if (field('handshake_hash') != null) {
          expect(
            toHex(written.handshakeHash!),
            field('handshake_hash'),
            reason: '$name handshake hash',
          );
        }
      } else {
        expect(read.transport, isNull);
        expect(written.handshakeHash, isNull);
      }
    }
  } finally {
    await initTransport?.close();
    await respTransport?.close();
    await initiator.close();
    await responder.close();
    await initStatic?.close();
    await respStatic?.close();
  }
}
