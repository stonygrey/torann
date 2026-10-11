// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// The example app is the package's device test. Each suite's result is written with
// console.log under the prefix TORANN, which is what the terminal running `expo run:ios`
// or `expo run:android` reads. The files under assets/vectors are copies written by
// lib/sync-reactnative-sources.

import { StatusBar } from 'expo-status-bar';
import { useEffect, useState } from 'react';
import { Platform, ScrollView, StyleSheet, Text, View } from 'react-native';
import { HandshakeState, KeyPair, NoiseProtocol, TorannError, Transport } from '@stonygrey/torann';
import { setFixedEphemeral } from '@stonygrey/torann/testing';

// Android (Kotlin) supports every function; iOS (Swift) supports the 25519/SHA-2 subset.
const full = Platform.OS === 'android';

interface Vector {
  protocol_name: string;
  init_prologue: string;
  resp_prologue: string;
  init_static?: string;
  resp_static?: string;
  init_remote_static?: string;
  resp_remote_static?: string;
  init_psks?: string[];
  resp_psks?: string[];
  init_ephemeral?: string;
  resp_ephemeral?: string;
  handshake_hash?: string;
  messages: { payload: string; ciphertext: string }[];
}

const files: Record<string, { vectors: Vector[] }> = {
  'cacophony.json': require('./assets/vectors/cacophony.json'),
  'snow.json': require('./assets/vectors/snow.json'),
};

function hex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(s.substring(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function assertEqual(actual: string, expected: string, what: string): void {
  if (actual !== expected) {
    throw new Error(`${what}: expected ${expected}, got ${actual}`);
  }
}

function expectCode(fn: () => unknown, code: string, what: string): TorannError {
  try {
    fn();
  } catch (e) {
    if (e instanceof TorannError && e.code === code) {
      return e;
    }
    throw new Error(`${what}: expected TorannError ${code}, got ${String(e)}`);
  }
  throw new Error(`${what}: expected TorannError ${code}, nothing was thrown`);
}

/** Test data only: payloads and a test PSK. The library draws its own keys from the platform. */
function testBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    out[i] = Math.floor(Math.random() * 256);
  }
  return out;
}

const yieldToUi = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

async function runFile(fileName: string, expectedRun: number, expectedSkipped: number): Promise<string> {
  let run = 0;
  let skipped = 0;
  for (const vector of files[fileName].vectors) {
    let protocol: NoiseProtocol;
    try {
      protocol = NoiseProtocol.parse(vector.protocol_name);
    } catch (e) {
      if (e instanceof TorannError && e.code === 'unsupportedFunction') {
        skipped++;
        continue;
      }
      throw e;
    }
    try {
      runVector(protocol, vector);
    } catch (e) {
      throw new Error(`Vector '${vector.protocol_name}' failed: ${String(e)}`);
    }
    run++;
    if (run % 25 === 0) {
      await yieldToUi();
    }
  }
  const line = `${fileName}: ran ${run} vectors, skipped ${skipped} unsupported.`;
  if (run !== expectedRun || skipped !== expectedSkipped) {
    throw new Error(`${line} Expected ${expectedRun} run and ${expectedSkipped} skipped.`);
  }
  return line;
}

function runVector(protocol: NoiseProtocol, vector: Vector): void {
  const name = vector.protocol_name;
  const psks = (list?: string[]) => (list ?? []).map(hex);
  const initStatic = vector.init_static === undefined ? undefined : protocol.createKeyPair(hex(vector.init_static));
  const respStatic = vector.resp_static === undefined ? undefined : protocol.createKeyPair(hex(vector.resp_static));
  const initiator = protocol.createHandshake({
    initiator: true,
    prologue: hex(vector.init_prologue),
    localStatic: initStatic,
    remoteStatic: vector.init_remote_static === undefined ? undefined : hex(vector.init_remote_static),
    psks: psks(vector.init_psks),
  });
  if (vector.init_ephemeral !== undefined) {
    setFixedEphemeral(initiator, hex(vector.init_ephemeral));
  }
  const responder = protocol.createHandshake({
    initiator: false,
    prologue: hex(vector.resp_prologue),
    localStatic: respStatic,
    remoteStatic: vector.resp_remote_static === undefined ? undefined : hex(vector.resp_remote_static),
    psks: psks(vector.resp_psks),
  });
  if (vector.resp_ephemeral !== undefined) {
    setFixedEphemeral(responder, hex(vector.resp_ephemeral));
  }

  let initTransport: Transport | null = null;
  let respTransport: Transport | null = null;
  let oneWay = false;
  try {
    for (let i = 0; i < vector.messages.length; i++) {
      const payload = vector.messages[i].payload;
      const expected = vector.messages[i].ciphertext;
      const initiatorSends = oneWay || i % 2 === 0;

      if (initTransport !== null && respTransport !== null) {
        const writer = initiatorSends ? initTransport : respTransport;
        const reader = initiatorSends ? respTransport : initTransport;
        assertEqual(toHex(writer.writeMessage(hex(payload))), expected, `${name} transport message ${i}`);
        assertEqual(toHex(reader.readMessage(hex(expected))), payload, `${name} transport payload ${i}`);
        continue;
      }

      const writer = initiatorSends ? initiator : responder;
      const reader = initiatorSends ? responder : initiator;
      const written = writer.writeMessage(hex(payload));
      assertEqual(toHex(written.message), expected, `${name} message ${i}`);
      const read = reader.readMessage(hex(expected));
      assertEqual(toHex(read.payload), payload, `${name} payload ${i}`);

      if (written.transport !== null) {
        if (read.transport === null || read.handshakeHash === null || written.handshakeHash === null) {
          throw new Error(`${name}: the reader produced no transport`);
        }
        initTransport = initiatorSends ? written.transport : read.transport;
        respTransport = initiatorSends ? read.transport : written.transport;
        if (i === 0) {
          oneWay = true;
        }
        assertEqual(toHex(read.handshakeHash), toHex(written.handshakeHash), `${name} handshake hashes differ`);
        if (vector.handshake_hash !== undefined) {
          assertEqual(toHex(written.handshakeHash), vector.handshake_hash, `${name} handshake hash`);
        }
      } else if (read.transport !== null || written.handshakeHash !== null) {
        throw new Error(`${name}: a transport appeared before the final message`);
      }
    }
  } finally {
    initTransport?.close();
    respTransport?.close();
    initiator.close();
    responder.close();
    initStatic?.close();
    respStatic?.close();
  }
}

async function randomKeyHandshakes(): Promise<string> {
  const names = [
    'Noise_NN_25519_ChaChaPoly_SHA256',
    'Noise_XX_25519_ChaChaPoly_SHA256',
    'Noise_IK_25519_AESGCM_SHA512',
    'Noise_XXpsk3_25519_ChaChaPoly_SHA256',
    ...(full ? ['Noise_XX_448_ChaChaPoly_BLAKE2s'] : []),
  ];
  const ping = new Uint8Array([0x70, 0x69, 0x6e, 0x67]);
  for (const name of names) {
    const protocol = NoiseProtocol.parse(name);
    const initStatic = protocol.generateKeyPair();
    const respStatic = protocol.generateKeyPair();
    const psks = name.includes('psk') ? [testBytes(32)] : [];
    const initiator = protocol.createHandshake({
      initiator: true,
      localStatic: initStatic,
      remoteStatic: name.includes('_IK') ? respStatic.publicKey : undefined,
      psks,
    });
    const responder = protocol.createHandshake({ initiator: false, localStatic: respStatic, psks });

    let writer: HandshakeState = initiator;
    let reader: HandshakeState = responder;
    let initTransport: Transport | null = null;
    let respTransport: Transport | null = null;
    try {
      while (initTransport === null) {
        const written = writer.writeMessage(ping);
        const read = reader.readMessage(written.message);
        assertEqual(toHex(read.payload), toHex(ping), `${name} payload`);
        if (written.transport !== null) {
          assertEqual(toHex(read.handshakeHash!), toHex(written.handshakeHash!), `${name} handshake hash`);
          initTransport = writer === initiator ? written.transport : read.transport;
          respTransport = writer === initiator ? read.transport : written.transport;
        }
        [writer, reader] = [reader, writer];
      }
      if (!name.includes('_NN')) {
        assertEqual(toHex(initiator.remoteStaticPublicKey()!), toHex(respStatic.publicKey), `${name} remote static`);
      }
      const data = testBytes(1024);
      assertEqual(toHex(respTransport!.readMessage(initTransport.writeMessage(data))), toHex(data), `${name} transport`);
      initTransport.rekeySend();
      respTransport!.rekeyReceive();
      assertEqual(toHex(respTransport!.readMessage(initTransport.writeMessage(data))), toHex(data), `${name} after rekey`);

      const tampered = new Uint8Array(initTransport.writeMessage(data));
      tampered[0] ^= 0xff;
      expectCode(() => respTransport!.readMessage(tampered), 'authenticationFailed', `${name} tampered`);

      initTransport.close();
      expectCode(() => initTransport!.writeMessage(data), 'closed', `${name} closed transport`);
    } finally {
      initTransport?.close();
      respTransport?.close();
      initiator.close();
      responder.close();
      initStatic.close();
      respStatic.close();
    }
    await yieldToUi();
  }
  return `${names.length} patterns completed with random keys; rekey, tamper, and close checked.`;
}

async function rfc7748(): Promise<string> {
  const x25519 = NoiseProtocol.parse('Noise_NN_25519_ChaChaPoly_SHA256');
  const alice: KeyPair = x25519.createKeyPair(hex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'));
  assertEqual(toHex(alice.publicKey), '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a', 'X25519 public key');
  alice.close();
  if (!full) {
    return 'X25519 public key matches RFC 7748 §6.1.';
  }
  const x448 = NoiseProtocol.parse('Noise_NN_448_ChaChaPoly_SHA256');
  const bob = x448.createKeyPair(
    hex('1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d')
  );
  assertEqual(
    toHex(bob.publicKey),
    '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609',
    'X448 public key'
  );
  bob.close();
  return 'X25519 and X448 public keys match RFC 7748 §6.';
}

async function functionSet(): Promise<string> {
  if (full) {
    assertEqual(NoiseProtocol.parse('Noise_XX_448_ChaChaPoly_BLAKE2b').name, 'Noise_XX_448_ChaChaPoly_BLAKE2b', 'full set');
  } else {
    const e = expectCode(() => NoiseProtocol.parse('Noise_XX_448_ChaChaPoly_SHA256'), 'unsupportedFunction', '448 on iOS');
    assertEqual(e.message, "DH function '448' is not supported.", 'unsupported message');
  }
  expectCode(() => NoiseProtocol.parse('Noise_XX_25519_ChaChaPoly'), 'invalidProtocolName', 'short name');
  return full ? 'Every function parses on Android.' : 'The Swift subset is enforced by name on iOS.';
}

const suites: { name: string; run: () => Promise<string> }[] = [
  { name: 'cacophony vectors', run: () => runFile('cacophony.json', full ? 944 : 236, full ? 0 : 708) },
  { name: 'snow vectors', run: () => runFile('snow.json', full ? 408 : 204, full ? 0 : 204) },
  { name: 'random-key handshakes', run: randomKeyHandshakes },
  { name: 'RFC 7748', run: rfc7748 },
  { name: 'function set', run: functionSet },
];

interface Line {
  name: string;
  state: 'running' | 'pass' | 'fail';
  detail: string;
}

export default function App() {
  const [lines, setLines] = useState<Line[]>([]);
  const [summary, setSummary] = useState('running');

  useEffect(() => {
    let cancelled = false;
    // Fast Refresh re-runs the effect while keeping the state, so the list starts empty each time.
    setLines([]);
    setSummary('running');
    (async () => {
      let failed = 0;
      for (const suite of suites) {
        if (cancelled) return;
        setLines((l) => [...l, { name: suite.name, state: 'running', detail: '' }]);
        await yieldToUi();
        let line: Line;
        try {
          line = { name: suite.name, state: 'pass', detail: await suite.run() };
        } catch (e) {
          failed++;
          line = { name: suite.name, state: 'fail', detail: String(e) };
        }
        console.log(`TORANN ${line.state.toUpperCase()} ${line.name}: ${line.detail}`);
        setLines((l) => l.map((x) => (x.name === suite.name ? line : x)));
      }
      const text = failed === 0 ? `all ${suites.length} suites passed` : `${failed} of ${suites.length} suites failed`;
      console.log(`TORANN SUMMARY ${Platform.OS}: ${text}`);
      setSummary(text);
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <View style={styles.container}>
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>Torann on {Platform.OS}</Text>
        <Text style={styles.summary}>{summary}</Text>
        {lines.map((line) => (
          <Text key={line.name} style={[styles.line, line.state === 'fail' && styles.fail]}>
            {line.state === 'running' ? '…' : line.state === 'pass' ? 'PASS' : 'FAIL'} {line.name}
            {line.detail ? `\n${line.detail}` : ''}
          </Text>
        ))}
      </ScrollView>
      <StatusBar style="auto" />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#fff', paddingTop: Platform.select({ ios: 60, android: 40 }) },
  content: { padding: 16 },
  title: { fontSize: 20, fontWeight: '600', marginBottom: 8 },
  summary: { fontSize: 16, marginBottom: 16 },
  line: { fontFamily: Platform.select({ ios: 'Menlo', android: 'monospace' }), fontSize: 12, marginBottom: 12 },
  fail: { color: '#b00020' },
});
