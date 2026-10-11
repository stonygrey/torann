// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// Unit tests of the JavaScript layer against a fake native module: error mapping,
// closed-state tracking, nonce validation, and the plumbing of results. The
// cryptography is tested natively and in the example app on a device.

import { HandshakeState, KeyPair, NoiseProtocol, TorannError, Transport } from '../index';
import { setNativeModuleForTesting, type TorannNativeModule } from '../native';
import { setFixedEphemeral } from '../testing';

class CodedError extends Error {
  constructor(
    readonly code: string,
    message: string
  ) {
    super(message);
  }
}

const calls: string[] = [];

function fakeTransport(): any {
  return {
    writeMessage: (p: Uint8Array) => new Uint8Array(p.length + 16),
    readMessage: (m: Uint8Array) => new Uint8Array(m.length - 16),
    rekeySend: () => calls.push('rekeySend'),
    rekeyReceive: () => {
      throw new CodedError(
        'invalidState',
        "A one-way pattern's initiator cannot receive transport messages."
      );
    },
    setSendNonce: (n: number) => calls.push(`setSendNonce ${n}`),
    setReceiveNonce: () => undefined,
    close: () => calls.push('closeTransport'),
  };
}

function fakeHandshake(): any {
  let complete = false;
  let transport: any = fakeTransport();
  return {
    writeMessage: (p: Uint8Array) => {
      calls.push(`handshakeWrite ${p.length}`);
      complete = true;
      return new Uint8Array(48);
    },
    readMessage: () => {
      throw new CodedError('authenticationFailed', 'The handshake message is truncated.');
    },
    handshakeHash: () => (complete ? new Uint8Array(32) : null),
    takeTransport: () => {
      const t = transport;
      transport = null;
      return t;
    },
    remoteStaticPublicKey: () => null,
    close: () => calls.push('closeHandshake'),
    setFixedEphemeral: () => calls.push('setFixedEphemeral'),
  };
}

const fake = {
  parseProtocol: (name: string) => {
    calls.push(`parseProtocol ${name}`);
    if (!name.startsWith('Noise_'))
      throw new CodedError('invalidProtocolName', `'${name}' is not a valid Noise protocol name.`);
    if (name.includes('448'))
      throw new CodedError('unsupportedFunction', "DH function '448' is not supported.");
  },
  generateKeyPair: () => ({
    publicKey: () => new Uint8Array(32).fill(7),
    privateKey: () => new Uint8Array(32).fill(1),
    close: () => calls.push('closeKeyPair'),
  }),
  createKeyPair: (_: string, privateKey: Uint8Array) => {
    if (privateKey.length !== 32)
      throw new CodedError('invalidArgument', 'The private key must be 32 bytes.');
    return fake.generateKeyPair();
  },
  createHandshake: (
    name: string,
    initiator: boolean,
    prologue: Uint8Array,
    local: unknown,
    remote: unknown,
    psks: Uint8Array[]
  ) => {
    calls.push(
      `createHandshake ${name} ${initiator} ${prologue.length} ${local !== null} ${remote !== null} ${psks.length}`
    );
    return fakeHandshake();
  },
} as unknown as TorannNativeModule;

beforeEach(() => {
  calls.length = 0;
  setNativeModuleForTesting(fake);
});

afterEach(() => setNativeModuleForTesting(null));

test('parse keeps the name and maps parse errors to TorannError codes', () => {
  expect(NoiseProtocol.parse('Noise_XX_25519_ChaChaPoly_SHA256').name).toBe(
    'Noise_XX_25519_ChaChaPoly_SHA256'
  );
  expect(NoiseProtocol.maxMessageLength).toBe(65535);
  expect(() => NoiseProtocol.parse('Noise_XX_448_ChaChaPoly_SHA256')).toThrow(
    expect.objectContaining({
      code: 'unsupportedFunction',
      message: "DH function '448' is not supported.",
    })
  );
  expect(() => NoiseProtocol.parse('nonsense')).toThrow(
    expect.objectContaining({ code: 'invalidProtocolName' })
  );
});

test('key pairs return copies and track close', () => {
  const protocol = NoiseProtocol.parse('Noise_XX_25519_ChaChaPoly_SHA256');
  const keys = protocol.generateKeyPair();
  expect(keys).toBeInstanceOf(KeyPair);
  const first = keys.publicKey;
  first[0] = 0;
  expect(keys.publicKey[0]).toBe(7);
  expect(keys.privateKey()).toEqual(new Uint8Array(32).fill(1));
  expect(() => protocol.createKeyPair(new Uint8Array(31))).toThrow(
    expect.objectContaining({ code: 'invalidArgument' })
  );

  keys.close();
  keys.close();
  expect(calls.filter((c) => c === 'closeKeyPair')).toHaveLength(1);
  expect(() => keys.publicKey).toThrow(expect.objectContaining({ code: 'closed' }));
  expect(() => keys.privateKey()).toThrow(expect.objectContaining({ code: 'closed' }));
  expect(() => protocol.createHandshake({ initiator: true, localStatic: keys })).toThrow(
    expect.objectContaining({ code: 'closed' })
  );
});

test('handshakes pass arguments through, wrap results, and map errors', () => {
  const protocol = NoiseProtocol.parse('Noise_XX_25519_ChaChaPoly_SHA256');
  const keys = protocol.generateKeyPair();
  const handshake = protocol.createHandshake({
    initiator: true,
    localStatic: keys,
    psks: [new Uint8Array(32)],
  });
  expect(handshake).toBeInstanceOf(HandshakeState);
  expect(calls.at(-1)).toBe('createHandshake Noise_XX_25519_ChaChaPoly_SHA256 true 0 true false 1');

  const written = handshake.writeMessage(new Uint8Array(5));
  expect(written.message).toHaveLength(48);
  expect(written.handshakeHash).toHaveLength(32);
  expect(written.transport).toBeInstanceOf(Transport);

  expect(() => handshake.readMessage(new Uint8Array(3))).toThrow(
    expect.objectContaining({ code: 'authenticationFailed' })
  );

  const transport = written.transport!;
  expect(transport.writeMessage(new Uint8Array(10))).toHaveLength(26);
  transport.rekeySend();
  expect(() => transport.rekeyReceive()).toThrow(expect.objectContaining({ code: 'invalidState' }));
  expect(() => transport.setSendNonce(-1)).toThrow(
    expect.objectContaining({ code: 'invalidArgument' })
  );
  expect(() => transport.setSendNonce(1.5)).toThrow(
    expect.objectContaining({ code: 'invalidArgument' })
  );
  transport.setSendNonce(5);
  expect(calls.at(-1)).toBe('setSendNonce 5');

  setFixedEphemeral(handshake, new Uint8Array(32));
  expect(calls.at(-1)).toBe('setFixedEphemeral');

  transport.close();
  expect(() => transport.writeMessage(new Uint8Array(1))).toThrow(
    expect.objectContaining({ code: 'closed' })
  );
  handshake.close();
  expect(() => handshake.writeMessage()).toThrow(expect.objectContaining({ code: 'closed' }));
  expect(calls).toEqual(expect.arrayContaining(['closeTransport', 'closeHandshake']));
});

test('the host message is the text after the Expo cause marker', () => {
  const wrapped = {
    ...fake,
    parseProtocol: () => {
      throw new CodedError(
        'invalidState',
        "Calling the 'parseProtocol' function has failed (at ExpoModulesCore/SyncFunctionDefinition.swift:94)\n→ Caused by: The handshake has failed and must be discarded."
      );
    },
  } as unknown as TorannNativeModule;
  setNativeModuleForTesting(wrapped);
  expect(() => NoiseProtocol.parse('Noise_NN_25519_ChaChaPoly_SHA256')).toThrow(
    expect.objectContaining({
      code: 'invalidState',
      message: 'The handshake has failed and must be discarded.',
    })
  );
});

test('errors outside the six categories become hostFailure', () => {
  const broken = {
    ...fake,
    parseProtocol: () => {
      throw new CodedError('ERR_SOMETHING', 'Native exploded');
    },
  } as unknown as TorannNativeModule;
  setNativeModuleForTesting(broken);
  let caught: unknown;
  try {
    NoiseProtocol.parse('Noise_NN_25519_ChaChaPoly_SHA256');
  } catch (e) {
    caught = e;
  }
  expect(caught).toBeInstanceOf(TorannError);
  expect((caught as TorannError).code).toBe('hostFailure');
});
