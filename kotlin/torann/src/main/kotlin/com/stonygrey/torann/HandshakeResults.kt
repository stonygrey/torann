// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

/**
 * The result of [HandshakeState.writeMessage]. [handshakeHash] and [transport] are
 * present on the final message of the pattern only.
 */
class HandshakeWriteResult(val message: ByteArray, val handshakeHash: ByteArray?, val transport: Transport?)

/**
 * The result of [HandshakeState.readMessage]. [handshakeHash] and [transport] are
 * present on the final message of the pattern only.
 */
class HandshakeReadResult(val payload: ByteArray, val handshakeHash: ByteArray?, val transport: Transport?)
