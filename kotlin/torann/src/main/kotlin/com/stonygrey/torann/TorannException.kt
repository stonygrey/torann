// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

/**
 * The errors Torann raises, one subclass per category. No message contains key material.
 */
sealed class TorannException(message: String) : RuntimeException(message) {
    /** The name is not `Noise_` followed by four parts. */
    class InvalidProtocolName(message: String) : TorannException(message)

    /** The pattern, modifier, DH, cipher, or hash is not supported. */
    class UnsupportedFunction(message: String) : TorannException(message)

    /** A length, count, or required argument is wrong. The object remains usable. */
    class InvalidArgument(message: String) : TorannException(message)

    /** Wrong turn, handshake complete or failed, one-way direction, or nonce exhausted. */
    class InvalidState(message: String) : TorannException(message)

    /**
     * A message is truncated or its tag does not verify. During a handshake this is
     * terminal once a message pattern has been consumed.
     */
    class AuthenticationFailed(message: String) : TorannException(message)

    /** The object has been closed. */
    class Closed : TorannException("The object has been closed.")
}
