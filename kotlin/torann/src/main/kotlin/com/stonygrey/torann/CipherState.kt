// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

import com.stonygrey.torann.crypto.CipherFunction
import com.stonygrey.torann.crypto.CipherKey

/**
 * CipherState per Noise §5.1: an AEAD key plus a 64-bit nonce counter. Not thread-safe
 * on its own; [HandshakeState] and [Transport] hold the lock.
 */
internal class CipherState(private val cipher: CipherFunction) {
    private var key: CipherKey? = null
    private var nonce: ULong = 0u
    private var closed = false

    val hasKey: Boolean get() = !closed && key != null

    /** Installs the key and zeros [keyBytes]; callers pass a copy they no longer need. */
    fun initializeKey(keyBytes: ByteArray) {
        throwIfClosed()
        key?.close()
        key = cipher.createKey(keyBytes)
        keyBytes.wipe()
        nonce = 0u
    }

    fun setNonce(value: ULong) {
        throwIfClosed()
        if (value == ULong.MAX_VALUE) {
            throw TorannException.InvalidArgument("Nonce 2^64-1 is reserved.")
        }
        nonce = value
    }

    /** Rekey per Noise §11.3 / §4.2: k = ENCRYPT(k, 2^64-1, empty, zeros[32])[..32]. Does not reset n. */
    fun rekey() {
        throwIfClosed()
        val current = key ?: throw TorannException.InvalidState("Cannot rekey an empty CipherState.")
        val output = current.encrypt(ULong.MAX_VALUE, ByteArray(0), ByteArray(32))
        val newKey = output.copyOf(32)
        output.wipe()
        try {
            // The new key is created before the old one is closed, so a failure here
            // leaves the state usable.
            key = cipher.createKey(newKey)
            current.close()
        } finally {
            newKey.wipe()
        }
    }

    fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
        throwIfClosed()
        val k = key ?: return plaintext.copyOf()
        checkNonce()
        val ciphertext = k.encrypt(nonce, ad, plaintext)
        nonce++
        return ciphertext
    }

    fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray {
        throwIfClosed()
        val k = key ?: return ciphertext.copyOf()
        if (ciphertext.size < 16) {
            throw TorannException.AuthenticationFailed("Ciphertext is shorter than the authentication tag.")
        }
        checkNonce()
        val plaintext = k.decrypt(nonce, ad, ciphertext)
        nonce++
        return plaintext
    }

    private fun checkNonce() {
        // 2^64 - 1 is reserved (Noise §5.1).
        if (nonce == ULong.MAX_VALUE) {
            throw TorannException.InvalidState("Nonce exhausted; the session must be re-established.")
        }
    }

    private fun throwIfClosed() {
        if (closed) throw TorannException.Closed()
    }

    fun close() {
        if (closed) return
        closed = true
        key?.close()
        key = null
    }
}
