// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

/**
 * Torann: the Noise Protocol Framework for React Native, calling the Swift
 * implementation on iOS and the Kotlin implementation on Android. The JavaScript
 * layer holds no keys and does no cryptography; each object wraps a native object.
 */

import { TorannError, nativeCall } from './errors';
import {
  nativeModule,
  type NativeHandshakeState,
  type NativeKeyPair,
  type NativeTransport,
} from './native';

export { TorannError, type TorannErrorCode } from './errors';

function copy(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes);
}

function checkNonce(nonce: number): number {
  if (!Number.isSafeInteger(nonce) || nonce < 0) {
    throw new TorannError(
      'invalidArgument',
      'The nonce must be an integer from 0 to Number.MAX_SAFE_INTEGER.'
    );
  }
  return nonce;
}

/**
 * A parsed Noise protocol name such as `Noise_XX_25519_ChaChaPoly_SHA256`, and the
 * factory for key pairs and handshakes. The supported functions depend on the host:
 * Android (Kotlin) supports `25519`, `448`, `ChaChaPoly`, `AESGCM`, `SHA256`, `SHA512`,
 * `BLAKE2s`, and `BLAKE2b`; iOS (Swift) supports `25519`, `ChaChaPoly`, `AESGCM`,
 * `SHA256`, and `SHA512`. An application that runs on both platforms uses `25519` with
 * `SHA256` or `SHA512`.
 */
export class NoiseProtocol {
  /** Maximum length in bytes of a Noise handshake or transport message (Noise §3). */
  static readonly maxMessageLength = 65535;

  private constructor(readonly name: string) {}

  /** Parses a protocol name. Throws `invalidProtocolName` or `unsupportedFunction`. */
  static parse(name: string): NoiseProtocol {
    nativeCall(() => nativeModule().parseProtocol(name));
    return new NoiseProtocol(name);
  }

  /** Generates a fresh static key pair for this protocol's DH function. */
  generateKeyPair(): KeyPair {
    return new KeyPair(nativeCall(() => nativeModule().generateKeyPair(this.name)));
  }

  /** Reconstructs a key pair from a stored private key. */
  createKeyPair(privateKey: Uint8Array): KeyPair {
    return new KeyPair(nativeCall(() => nativeModule().createKeyPair(this.name, privateKey)));
  }

  /**
   * Creates a handshake. `initiator` is true for the party that sends the first
   * message. `prologue` is authenticated but not transmitted. `localStatic` is
   * required when the pattern sends or pre-shares this party's static key, and
   * `remoteStatic` when it pre-shares the peer's. `psks` holds one 32-byte key per
   * psk modifier, consumed in the order the `psk` tokens occur in the pattern. The
   * host copies every argument. A closed `localStatic` throws `closed` before the
   * host is called.
   */
  createHandshake(options: {
    initiator: boolean;
    prologue?: Uint8Array;
    localStatic?: KeyPair;
    remoteStatic?: Uint8Array;
    psks?: Uint8Array[];
  }): HandshakeState {
    const local = options.localStatic?.nativeForHost() ?? null;
    return new HandshakeState(
      nativeCall(() =>
        nativeModule().createHandshake(
          this.name,
          options.initiator,
          options.prologue ?? new Uint8Array(0),
          local,
          options.remoteStatic ?? null,
          options.psks ?? []
        )
      )
    );
  }
}

/** The constructors are for this module; application code obtains instances from `NoiseProtocol` and from handshake results. */
abstract class NativeBacked<N extends { close(): void }> {
  private closed = false;

  constructor(protected readonly native: N) {}

  protected require(): N {
    if (this.closed) {
      throw new TorannError('closed', 'The object has been closed.');
    }
    return this.native;
  }

  /** Releases the host object and wipes the key material it owns. Calling it twice has no further effect. */
  close(): void {
    if (this.closed) {
      return;
    }
    this.closed = true;
    nativeCall(() => this.native.close());
  }
}

/** A DH key pair held by the host. Every read returns a copy. */
export class KeyPair extends NativeBacked<NativeKeyPair> {
  /** A copy of the public key. Throws `closed` after `close()`. */
  get publicKey(): Uint8Array {
    const native = this.require();
    return copy(nativeCall(() => native.publicKey()));
  }

  /** A copy of the private key. Throws `closed` after `close()`. */
  privateKey(): Uint8Array {
    const native = this.require();
    return copy(nativeCall(() => native.privateKey()));
  }

  /** @internal */
  nativeForHost(): NativeKeyPair {
    return this.require();
  }
}

/** The result of `HandshakeState.writeMessage`. `handshakeHash` and `transport` are present on the final message only. */
export interface HandshakeWriteResult {
  readonly message: Uint8Array;
  readonly handshakeHash: Uint8Array | null;
  readonly transport: Transport | null;
}

/** The result of `HandshakeState.readMessage`. `handshakeHash` and `transport` are present on the final message only. */
export interface HandshakeReadResult {
  readonly payload: Uint8Array;
  readonly handshakeHash: Uint8Array | null;
  readonly transport: Transport | null;
}

/**
 * HandshakeState per Noise §5.3, held by the host. Call `writeMessage` and
 * `readMessage` alternately; the final message returns a `Transport`. A decrypt or DH
 * failure after a message pattern is consumed is terminal: the handshake refuses
 * further use and must be discarded.
 */
export class HandshakeState extends NativeBacked<NativeHandshakeState> {
  writeMessage(payload: Uint8Array = new Uint8Array(0)): HandshakeWriteResult {
    const native = this.require();
    const message = nativeCall(() => native.writeMessage(payload));
    return { message, ...this.completion(native) };
  }

  readMessage(message: Uint8Array): HandshakeReadResult {
    const native = this.require();
    const payload = nativeCall(() => native.readMessage(message));
    return { payload, ...this.completion(native) };
  }

  /**
   * The peer's static public key once known: at once when it was passed to
   * `createHandshake`, after the message that carried it otherwise. Null after a
   * terminal failure. Throws `closed` after `close()`.
   */
  remoteStaticPublicKey(): Uint8Array | null {
    const native = this.require();
    const key = nativeCall(() => native.remoteStaticPublicKey());
    return key === null ? null : copy(key);
  }

  /** @internal */
  nativeForTesting(): NativeHandshakeState {
    return this.require();
  }

  private completion(native: NativeHandshakeState): {
    handshakeHash: Uint8Array | null;
    transport: Transport | null;
  } {
    const hash = nativeCall(() => native.handshakeHash());
    if (hash === null) {
      return { handshakeHash: null, transport: null };
    }
    const transport = nativeCall(() => native.takeTransport());
    return { handshakeHash: hash, transport: transport === null ? null : new Transport(transport) };
  }
}

/**
 * Post-handshake transport state held by the host. A lost or reordered message
 * desynchronizes the nonces, and the application discards the transport after a
 * decrypt failure.
 */
export class Transport extends NativeBacked<NativeTransport> {
  /** Size in bytes of the AEAD authentication tag appended to every transport message. */
  static readonly tagSize = 16;

  /** Encrypts a payload of at most 65519 bytes. Returns ciphertext followed by the tag. */
  writeMessage(payload: Uint8Array): Uint8Array {
    const native = this.require();
    return nativeCall(() => native.writeMessage(payload));
  }

  readMessage(message: Uint8Array): Uint8Array {
    const native = this.require();
    return nativeCall(() => native.readMessage(message));
  }

  /** Rekeys the outgoing CipherState (Noise §11.3). Does not reset the nonce. */
  rekeySend(): void {
    const native = this.require();
    nativeCall(() => native.rekeySend());
  }

  /** Rekeys the incoming CipherState (Noise §11.3). Does not reset the nonce. */
  rekeyReceive(): void {
    const native = this.require();
    nativeCall(() => native.rekeyReceive());
  }

  /**
   * Sets the outgoing nonce. For out-of-order transport (Noise §11.4) only. A
   * JavaScript number carries 53 bits, so the range is 0 to `Number.MAX_SAFE_INTEGER`.
   */
  setSendNonce(nonce: number): void {
    const native = this.require();
    const value = checkNonce(nonce);
    nativeCall(() => native.setSendNonce(value));
  }

  /** Sets the incoming nonce. For out-of-order transport (Noise §11.4) only. */
  setReceiveNonce(nonce: number): void {
    const native = this.require();
    const value = checkNonce(nonce);
    nativeCall(() => native.setReceiveNonce(value));
  }
}
