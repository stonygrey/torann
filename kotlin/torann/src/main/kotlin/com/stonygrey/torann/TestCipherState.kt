// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

/**
 * Test-only access to a CipherState and to the raw AEAD for the rekey definition test.
 * [CipherState] itself stays internal.
 */
@TorannTestApi
class TestCipherState(cipherName: String, key: ByteArray) {
    private val state = CipherState(NoiseProtocol.cipherByName(cipherName)).also { it.initializeKey(checkedCopy(key)) }

    // `@JvmSynthetic` hides the methods from Java, which does not enforce the opt-in
    // marker. A constructor cannot carry the annotation.
    @JvmSynthetic
    fun setNonce(nonce: ULong) = state.setNonce(nonce)

    @JvmSynthetic
    fun rekey() = state.rekey()

    @JvmSynthetic
    fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray = state.encryptWithAd(ad, plaintext)

    @JvmSynthetic
    fun close() = state.close()

    companion object {
        /** A copy of a 32-byte key; any other length is InvalidArgument, not a provider exception. */
        private fun checkedCopy(key: ByteArray): ByteArray {
            if (key.size != 32) throw TorannException.InvalidArgument("The cipher key must be 32 bytes.")
            return key.copyOf()
        }

        /** ENCRYPT(k, n, ad, plaintext) with the named cipher: ciphertext followed by the tag. */
        @JvmSynthetic
        fun aeadEncrypt(cipherName: String, key: ByteArray, nonce: ULong, ad: ByteArray, plaintext: ByteArray): ByteArray {
            val keyCopy = checkedCopy(key)
            val k = NoiseProtocol.cipherByName(cipherName).createKey(keyCopy)
            try {
                return k.encrypt(nonce, ad, plaintext)
            } finally {
                k.close()
                keyCopy.wipe()
            }
        }
    }
}
