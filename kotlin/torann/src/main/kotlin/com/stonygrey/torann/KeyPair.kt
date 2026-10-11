// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

/**
 * A DH key pair. Create one with [NoiseProtocol.generateKeyPair] or
 * [NoiseProtocol.createKeyPair]. Every read returns a copy.
 */
class KeyPair internal constructor(privateKey: ByteArray, publicKey: ByteArray) : AutoCloseable {
    private val lock = Any()
    private var privateKeyBytes: ByteArray? = privateKey
    private val publicKeyBytes: ByteArray = publicKey
    private var closed = false

    /** The private key bytes. Raises [TorannException.Closed] after [close]. */
    val privateKey: ByteArray
        get() = synchronized(lock) {
            if (closed) throw TorannException.Closed()
            (privateKeyBytes ?: throw TorannException.Closed()).copyOf()
        }

    /** The public key bytes. Raises [TorannException.Closed] after [close]. */
    val publicKey: ByteArray
        get() = synchronized(lock) {
            if (closed) throw TorannException.Closed()
            publicKeyBytes.copyOf()
        }

    /** Zeros the private key. Reading either key afterwards raises [TorannException.Closed]. */
    override fun close() {
        synchronized(lock) {
            if (closed) return
            closed = true
            privateKeyBytes?.wipe()
            privateKeyBytes = null
        }
    }
}
