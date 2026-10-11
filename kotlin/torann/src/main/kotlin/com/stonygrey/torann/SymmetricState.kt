// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

import com.stonygrey.torann.crypto.CipherFunction
import com.stonygrey.torann.crypto.HashFunction
import com.stonygrey.torann.crypto.NoiseHkdf

/** SymmetricState per Noise §5.2: chaining key, handshake hash, and inner CipherState. */
internal class SymmetricState(protocolName: String, private val cipher: CipherFunction, private val hash: HashFunction) {
    private val cipherState = CipherState(cipher)
    private var ck: ByteArray
    private var h: ByteArray

    init {
        val name = protocolName.toByteArray(Charsets.US_ASCII)
        h = if (name.size <= hash.hashLen) name.copyOf(hash.hashLen) else hash.hash(name, ByteArray(0))
        ck = h.copyOf()
    }

    val cipherHasKey: Boolean get() = cipherState.hasKey

    fun mixHash(data: ByteArray) {
        h = hash.hash(h, data)
    }

    fun mixKey(inputKeyMaterial: ByteArray) {
        val outputs = NoiseHkdf.derive(hash, ck, inputKeyMaterial, 2)
        ck.wipe()
        ck = outputs.out1
        cipherState.initializeKey(outputs.out2.copyOf(32))
        outputs.out2.wipe()
    }

    fun mixKeyAndHash(inputKeyMaterial: ByteArray) {
        val outputs = NoiseHkdf.derive(hash, ck, inputKeyMaterial, 3)
        ck.wipe()
        ck = outputs.out1
        mixHash(outputs.out2)
        cipherState.initializeKey(outputs.out3!!.copyOf(32))
        outputs.out2.wipe()
        outputs.out3.wipe()
    }

    fun encryptAndHash(plaintext: ByteArray): ByteArray {
        val ciphertext = cipherState.encryptWithAd(h, plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    fun decryptAndHash(ciphertext: ByteArray): ByteArray {
        val plaintext = cipherState.decryptWithAd(h, ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    fun split(): Pair<CipherState, CipherState> {
        val outputs = NoiseHkdf.derive(hash, ck, ByteArray(0), 2)
        val c1 = CipherState(cipher).also { it.initializeKey(outputs.out1.copyOf(32)) }
        val c2 = CipherState(cipher).also { it.initializeKey(outputs.out2.copyOf(32)) }
        outputs.wipe()
        return Pair(c1, c2)
    }

    val handshakeHash: ByteArray get() = h.copyOf()

    /** Zeros ck and the handshake CipherState after Split, leaving h for channel binding. */
    fun clearSecrets() {
        cipherState.close()
        ck.wipe()
    }

    fun close() {
        cipherState.close()
        ck.wipe()
    }
}
