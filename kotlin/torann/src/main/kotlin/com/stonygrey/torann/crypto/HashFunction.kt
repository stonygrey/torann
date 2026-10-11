// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann.crypto

import org.bouncycastle.crypto.Digest
import org.bouncycastle.crypto.digests.Blake2bDigest
import org.bouncycastle.crypto.digests.Blake2sDigest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** A Noise hash function (Noise §4.3). */
internal interface HashFunction {
    val name: String
    val hashLen: Int
    val blockLen: Int

    /** HASH(a || b) */
    fun hash(a: ByteArray, b: ByteArray): ByteArray

    /** HMAC-HASH(key, a || b) */
    fun hmac(key: ByteArray, a: ByteArray, b: ByteArray): ByteArray
}

internal class Sha2Hash(
    override val name: String,
    private val digestName: String,
    private val macName: String,
    override val hashLen: Int,
    override val blockLen: Int,
) : HashFunction {
    override fun hash(a: ByteArray, b: ByteArray): ByteArray {
        val digest = MessageDigest.getInstance(digestName)
        digest.update(a)
        if (b.isNotEmpty()) digest.update(b)
        return digest.digest()
    }

    override fun hmac(key: ByteArray, a: ByteArray, b: ByteArray): ByteArray {
        val mac = Mac.getInstance(macName)
        mac.init(SecretKeySpec(key, macName))
        mac.update(a)
        if (b.isNotEmpty()) mac.update(b)
        return mac.doFinal()
    }

    companion object {
        val SHA256 = Sha2Hash("SHA256", "SHA-256", "HmacSHA256", 32, 64)
        val SHA512 = Sha2Hash("SHA512", "SHA-512", "HmacSHA512", 64, 128)
    }
}

/**
 * Noise uses the HMAC construction over BLAKE2 (Noise §4.3), not BLAKE2's keyed mode;
 * Bouncy Castle's `HMac` reads the 64- or 128-byte block size from the digest.
 */
internal class Blake2Hash(
    override val name: String,
    override val hashLen: Int,
    override val blockLen: Int,
) : HashFunction {
    private fun createDigest(): Digest = if (hashLen == 32) Blake2sDigest(256) else Blake2bDigest(512)

    override fun hash(a: ByteArray, b: ByteArray): ByteArray {
        val digest = createDigest()
        digest.update(a, 0, a.size)
        if (b.isNotEmpty()) digest.update(b, 0, b.size)
        val result = ByteArray(hashLen)
        digest.doFinal(result, 0)
        return result
    }

    override fun hmac(key: ByteArray, a: ByteArray, b: ByteArray): ByteArray {
        val mac = HMac(createDigest())
        mac.init(KeyParameter(key))
        mac.update(a, 0, a.size)
        if (b.isNotEmpty()) mac.update(b, 0, b.size)
        val result = ByteArray(hashLen)
        mac.doFinal(result, 0)
        return result
    }

    companion object {
        val BLAKE2S = Blake2Hash("BLAKE2s", 32, 64)
        val BLAKE2B = Blake2Hash("BLAKE2b", 64, 128)
    }
}
