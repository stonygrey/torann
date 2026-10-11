// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import { NativeModule, requireNativeModule, SharedObject } from 'expo';

/**
 * Declarations of the native module and its three shared-object classes. Errors
 * arrive as coded errors whose `code` is one of the six Torann categories, or
 * `hostFailure`.
 */
export declare class NativeKeyPair extends SharedObject {
  publicKey(): Uint8Array;
  privateKey(): Uint8Array;
  close(): void;
}

export declare class NativeHandshakeState extends SharedObject {
  /** Returns the message to send. After the final message, `handshakeHash()` and `takeTransport()` are set. */
  writeMessage(payload: Uint8Array): Uint8Array;
  readMessage(message: Uint8Array): Uint8Array;
  handshakeHash(): Uint8Array | null;
  /** Returns the transport created by the final message on the first call and null afterwards. */
  takeTransport(): NativeTransport | null;
  remoteStaticPublicKey(): Uint8Array | null;
  close(): void;
  /** Test-only; exported through `@stonygrey/torann/testing`. */
  setFixedEphemeral(privateKey: Uint8Array): void;
}

export declare class NativeTransport extends SharedObject {
  writeMessage(payload: Uint8Array): Uint8Array;
  readMessage(message: Uint8Array): Uint8Array;
  rekeySend(): void;
  rekeyReceive(): void;
  setSendNonce(nonce: number): void;
  setReceiveNonce(nonce: number): void;
  close(): void;
}

export declare class TorannNativeModule extends NativeModule {
  parseProtocol(name: string): void;
  generateKeyPair(protocol: string): NativeKeyPair;
  createKeyPair(protocol: string, privateKey: Uint8Array): NativeKeyPair;
  createHandshake(
    protocol: string,
    initiator: boolean,
    prologue: Uint8Array,
    localStatic: NativeKeyPair | null,
    remoteStatic: Uint8Array | null,
    psks: Uint8Array[]
  ): NativeHandshakeState;
}

let override: TorannNativeModule | null = null;

/** The unit tests replace the module with a fake through `setNativeModuleForTesting`. */
export function nativeModule(): TorannNativeModule {
  return override ?? requireNativeModule<TorannNativeModule>('Torann');
}

/** For the package's own unit tests only. */
export function setNativeModuleForTesting(module: TorannNativeModule | null): void {
  override = module;
}
