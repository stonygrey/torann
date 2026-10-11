// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann.crypto

import com.stonygrey.torann.wipe

/**
 * The HKDF variant of Noise §4.3: two or three full-hash-length outputs and no info
 * parameter. It is not RFC 5869 HKDF.
 */
internal object NoiseHkdf {
    class Outputs(val out1: ByteArray, val out2: ByteArray, val out3: ByteArray?) {
        fun wipe() {
            out1.wipe()
            out2.wipe()
            out3?.wipe()
        }
    }

    fun derive(hash: HashFunction, chainingKey: ByteArray, inputKeyMaterial: ByteArray, outputs: Int): Outputs {
        val tempKey = hash.hmac(chainingKey, inputKeyMaterial, ByteArray(0))
        val out1 = hash.hmac(tempKey, byteArrayOf(0x01), ByteArray(0))
        val out2 = hash.hmac(tempKey, out1, byteArrayOf(0x02))
        val out3 = if (outputs == 3) hash.hmac(tempKey, out2, byteArrayOf(0x03)) else null
        tempKey.wipe()
        return Outputs(out1, out2, out3)
    }
}
