// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann.crypto

import com.stonygrey.torann.TorannException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.GeneralSecurityException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** A Noise cipher function (Noise §4.2). */
internal interface CipherFunction {
    val name: String
    fun createKey(key: ByteArray): CipherKey
}

/** An AEAD key. Output is ciphertext followed by the 16-byte tag. */
internal interface CipherKey {
    fun encrypt(nonce: ULong, ad: ByteArray, plaintext: ByteArray): ByteArray
    fun decrypt(nonce: ULong, ad: ByteArray, ciphertext: ByteArray): ByteArray
    fun close()
}

internal const val TAG_MISMATCH = "The authentication tag did not match."

/**
 * 4 zero bytes followed by the 64-bit counter, in the byte order the cipher defines. The
 * absolute `putLong(index, value)` exists on `ByteBuffer` on every Android API level; the
 * covariant `position()` override does not before API 34.
 */
internal fun nonceBytes(nonce: ULong, order: ByteOrder): ByteArray =
    ByteBuffer.allocate(12).order(order).putLong(4, nonce.toLong()).array()

/**
 * A JCA AEAD key. A new [Cipher] instance is created for every operation, because the
 * JDK's providers refuse to initialize one instance for encryption twice with the same
 * key and nonce. The key material lives in a [SecretKeySpec], which the library cannot
 * zero; `close()` drops the reference.
 */
private class JcaKey(
    key: ByteArray,
    keyAlgorithm: String,
    private val transformation: String,
    private val order: ByteOrder,
    private val parameters: (ByteArray) -> java.security.spec.AlgorithmParameterSpec,
) : CipherKey {
    private var spec: SecretKeySpec? = SecretKeySpec(key, keyAlgorithm)

    override fun encrypt(nonce: ULong, ad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = init(Cipher.ENCRYPT_MODE, nonce, ad)
        return cipher.doFinal(plaintext)
    }

    override fun decrypt(nonce: ULong, ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = init(Cipher.DECRYPT_MODE, nonce, ad)
        try {
            return cipher.doFinal(ciphertext)
        } catch (_: BadPaddingException) {
            // AEADBadTagException is a BadPaddingException; some providers throw the parent.
            throw TorannException.AuthenticationFailed(TAG_MISMATCH)
        }
    }

    private fun init(mode: Int, nonce: ULong, ad: ByteArray): Cipher {
        val key = spec ?: throw TorannException.Closed()
        val cipher = Cipher.getInstance(transformation)
        cipher.init(mode, key, parameters(nonceBytes(nonce, order)))
        if (ad.isNotEmpty()) {
            cipher.updateAAD(ad)
        }
        return cipher
    }

    override fun close() {
        spec = null
    }
}

/** AES-256-GCM per Noise §12.4: big-endian counter. `AES/GCM/NoPadding` appends the tag. */
internal object AesGcmCipher : CipherFunction {
    override val name = "AESGCM"

    override fun createKey(key: ByteArray): CipherKey =
        JcaKey(key, "AES", "AES/GCM/NoPadding", ByteOrder.BIG_ENDIAN) { GCMParameterSpec(128, it) }
}

/**
 * ChaCha20-Poly1305 per Noise §12.3: little-endian counter. The transformation name is
 * `ChaCha20-Poly1305` on the JDK and `ChaCha20/Poly1305/NoPadding` on Android, so it is
 * resolved once, the first time a key is created.
 */
internal object ChaChaPolyCipher : CipherFunction {
    override val name = "ChaChaPoly"

    private val transformation: String by lazy {
        for (candidate in listOf("ChaCha20-Poly1305", "ChaCha20/Poly1305/NoPadding")) {
            try {
                Cipher.getInstance(candidate)
                return@lazy candidate
            } catch (_: GeneralSecurityException) {
            }
        }
        throw TorannException.UnsupportedFunction("Cipher function 'ChaChaPoly' is not available on this platform.")
    }

    /** Resolves the transformation name now, so a platform without ChaCha20-Poly1305 fails at parse time. */
    fun ensureAvailable() {
        transformation
    }

    override fun createKey(key: ByteArray): CipherKey =
        JcaKey(key, "ChaCha20", transformation, ByteOrder.LITTLE_ENDIAN) { IvParameterSpec(it) }
}
