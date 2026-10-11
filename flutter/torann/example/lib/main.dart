// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:torann/torann.dart';

void main() {
  runApp(const TorannExampleApp());
}

/// Runs an XX handshake between two local parties once and shows the result. The
/// example exists to host the integration tests; this screen only proves the plugin
/// loads.
class TorannExampleApp extends StatefulWidget {
  const TorannExampleApp({super.key});

  @override
  State<TorannExampleApp> createState() => _TorannExampleAppState();
}

class _TorannExampleAppState extends State<TorannExampleApp> {
  late final Future<String> _result = _demonstrate();

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text('Torann')),
        body: FutureBuilder<String>(
          future: _result,
          builder: (context, snapshot) => Center(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Text(
                snapshot.hasError
                    ? 'Error: ${snapshot.error}'
                    : snapshot.data ?? 'Running XX handshake…',
              ),
            ),
          ),
        ),
      ),
    );
  }

  static Future<String> _demonstrate() async {
    final protocol = await NoiseProtocol.parse(
      'Noise_XX_25519_ChaChaPoly_SHA256',
    );
    final initiatorStatic = await protocol.generateKeyPair();
    final responderStatic = await protocol.generateKeyPair();
    HandshakeState? initiator, responder;
    Transport? initiatorTransport, responderTransport;
    try {
      initiator = await protocol.createHandshake(
        initiator: true,
        localStatic: initiatorStatic,
      );
      responder = await protocol.createHandshake(
        initiator: false,
        localStatic: responderStatic,
      );

      final m1 = await initiator.writeMessage();
      await responder.readMessage(m1.message);
      final m2 = await responder.writeMessage();
      await initiator.readMessage(m2.message);
      final m3 = await initiator.writeMessage(utf8.encode('hello'));
      final r3 = await responder.readMessage(m3.message);
      initiatorTransport = m3.transport;
      responderTransport = r3.transport;

      final hash = base64.encode(m3.handshakeHash!);
      final payload = utf8.decode(r3.payload);
      return '${protocol.name}\nhandshake hash (base64): $hash\npayload in message 3: $payload';
    } finally {
      await initiatorTransport?.close();
      await responderTransport?.close();
      await initiator?.close();
      await responder?.close();
      await initiatorStatic.close();
      await responderStatic.close();
    }
  }
}
