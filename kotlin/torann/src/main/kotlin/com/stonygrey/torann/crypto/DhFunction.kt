// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann.crypto

import com.stonygrey.torann.TorannException
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.math.ec.rfc7748.X448
import java.security.SecureRandom

/** A Noise DH function (Noise §4.1). */
internal interface DhFunction {
    val name: String
    val dhLen: Int
    fun generatePrivateKey(): ByteArray
    fun derivePublicKey(privateKey: ByteArray): ByteArray

    /**
     * Raises [TorannException.AuthenticationFailed] when the output would be all zeros,
     * which is terminal for the handshake.
     */
    fun dh(privateKey: ByteArray, publicKey: ByteArray): ByteArray
}

internal const val INVALID_PEER_KEY = "The peer's public key is invalid."

private val random = SecureRandom()

/**
 * The private key is raw random bytes; Bouncy Castle clamps inside the scalar
 * multiplication. `calculateAgreement` returns false for an all-zero output.
 */
internal object Curve25519Dh : DhFunction {
    override val name = "25519"
    override val dhLen = 32

    override fun generatePrivateKey(): ByteArray = ByteArray(dhLen).also(random::nextBytes)

    override fun derivePublicKey(privateKey: ByteArray): ByteArray {
        val result = ByteArray(dhLen)
        X25519.scalarMultBase(privateKey, 0, result, 0)
        return result
    }

    override fun dh(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val result = ByteArray(dhLen)
        if (!X25519.calculateAgreement(privateKey, 0, publicKey, 0, result, 0)) {
            throw TorannException.AuthenticationFailed(INVALID_PEER_KEY)
        }
        return result
    }
}

internal object Curve448Dh : DhFunction {
    override val name = "448"
    override val dhLen = 56

    override fun generatePrivateKey(): ByteArray = ByteArray(dhLen).also(random::nextBytes)

    override fun derivePublicKey(privateKey: ByteArray): ByteArray {
        val result = ByteArray(dhLen)
        X448.scalarMultBase(privateKey, 0, result, 0)
        return result
    }

    override fun dh(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        val result = ByteArray(dhLen)
        if (!X448.calculateAgreement(privateKey, 0, publicKey, 0, result, 0)) {
            throw TorannException.AuthenticationFailed(INVALID_PEER_KEY)
        }
        return result
    }
}
