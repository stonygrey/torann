// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

/**
 * Test-only entry points, imported as `@stonygrey/torann/testing`. Application code
 * must not import this module.
 */

import { nativeCall } from './errors';
import type { HandshakeState } from './index';

/** Installs the ephemeral private key the next `e` token uses instead of a random one, as the vector suites prescribe. Call it before the message that carries this party's `e` token. */
export function setFixedEphemeral(handshake: HandshakeState, privateKey: Uint8Array): void {
  const native = handshake.nativeForTesting();
  nativeCall(() => native.setFixedEphemeral(privateKey));
}
