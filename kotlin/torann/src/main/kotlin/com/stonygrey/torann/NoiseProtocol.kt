// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

import com.stonygrey.torann.crypto.AesGcmCipher
import com.stonygrey.torann.crypto.Blake2Hash
import com.stonygrey.torann.crypto.ChaChaPolyCipher
import com.stonygrey.torann.crypto.CipherFunction
import com.stonygrey.torann.crypto.Curve25519Dh
import com.stonygrey.torann.crypto.Curve448Dh
import com.stonygrey.torann.crypto.DhFunction
import com.stonygrey.torann.crypto.HashFunction
import com.stonygrey.torann.crypto.Sha2Hash

/**
 * A parsed Noise protocol name such as `Noise_XX_25519_ChaChaPoly_SHA256`, and the
 * factory for key pairs and handshakes. Supported functions: DH `25519` and `448`,
 * ciphers `ChaChaPoly` and `AESGCM`, hashes `SHA256`, `SHA512`, `BLAKE2s`, and `BLAKE2b`.
 */
class NoiseProtocol private constructor(
    /** The full protocol name, exactly as parsed. */
    val name: String,
    internal val pattern: HandshakePattern,
    internal val cipher: CipherFunction,
    internal val hash: HashFunction,
    internal val dh: DhFunction,
    internal val pskCount: Int,
) {
    companion object {
        /** Maximum length in bytes of a Noise handshake or transport message (Noise §3). */
        const val MAX_MESSAGE_LENGTH = 65535

        /**
         * Parses `Noise_{pattern}{modifiers}_{dh}_{cipher}_{hash}`. The checks run in the
         * order pattern, modifiers, psk range, DH, cipher, hash, and the first failure is
         * reported.
         */
        @JvmStatic
        fun parse(name: String): NoiseProtocol {
            val parts = name.split('_')
            if (parts.size != 5 || parts[0] != "Noise") {
                throw TorannException.InvalidProtocolName("'$name' is not a valid Noise protocol name.")
            }

            // Deferred pattern names carry digits (NK1, X1X1); modifiers start with a
            // lower-case letter.
            val patternPart = parts[1]
            val patternName = patternPart.takeWhile { it in 'A'..'Z' || it in '0'..'9' }
            var pattern = HandshakePattern.find(patternName)
                ?: throw TorannException.UnsupportedFunction("Handshake pattern '$patternName' is not supported.")

            val pskPositions = ArrayList<Int>()
            if (patternName.length < patternPart.length) {
                for (modifier in patternPart.substring(patternName.length).split('+')) {
                    val position = if (modifier.startsWith("psk")) parsePskPosition(modifier.substring(3)) else null
                    pskPositions.add(position ?: throw TorannException.UnsupportedFunction("Pattern modifier '$modifier' is not supported."))
                }
            }

            pattern = pattern.withPsks(pskPositions)

            val dh: DhFunction = when (parts[2]) {
                "25519" -> Curve25519Dh
                "448" -> Curve448Dh
                else -> throw TorannException.UnsupportedFunction("DH function '${parts[2]}' is not supported.")
            }

            val cipher = cipherByName(parts[3])

            val hash: HashFunction = when (parts[4]) {
                "SHA256" -> Sha2Hash.SHA256
                "SHA512" -> Sha2Hash.SHA512
                "BLAKE2s" -> Blake2Hash.BLAKE2S
                "BLAKE2b" -> Blake2Hash.BLAKE2B
                else -> throw TorannException.UnsupportedFunction("Hash function '${parts[4]}' is not supported.")
            }

            return NoiseProtocol(name, pattern, cipher, hash, dh, pskPositions.size)
        }

        internal fun cipherByName(name: String): CipherFunction = when (name) {
            "ChaChaPoly" -> ChaChaPolyCipher.also { it.ensureAvailable() }
            "AESGCM" -> AesGcmCipher
            else -> throw TorannException.UnsupportedFunction("Cipher function '$name' is not supported.")
        }

        /**
         * ASCII digits only: a sign or white space after `psk` is rejected.
         */
        private fun parsePskPosition(digits: String): Int? =
            if (digits.isNotEmpty() && digits.all { it in '0'..'9' }) digits.toIntOrNull() else null
    }

    /** Generates a fresh static key pair for this protocol's DH function. */
    fun generateKeyPair(): KeyPair {
        val privateKey = dh.generatePrivateKey()
        try {
            return KeyPair(privateKey.copyOf(), dh.derivePublicKey(privateKey))
        } finally {
            privateKey.wipe()
        }
    }

    /** Reconstructs a key pair from a stored private key. */
    fun createKeyPair(privateKey: ByteArray): KeyPair {
        if (privateKey.size != dh.dhLen) {
            throw TorannException.InvalidArgument("The private key must be ${dh.dhLen} bytes.")
        }
        return KeyPair(privateKey.copyOf(), dh.derivePublicKey(privateKey))
    }

    /**
     * Creates a handshake. [initiator] is true for the party that sends the first
     * message. [prologue] is authenticated but not transmitted. [localStatic] is
     * required when the pattern sends or pre-shares this party's static key, and
     * [remoteStatic] when it pre-shares the peer's. [psks] holds one 32-byte key per
     * psk modifier, consumed in the order the `psk` tokens occur in the pattern. Every argument is copied.
     */
    @JvmOverloads
    fun createHandshake(
        initiator: Boolean,
        prologue: ByteArray = ByteArray(0),
        localStatic: KeyPair? = null,
        remoteStatic: ByteArray? = null,
        psks: List<ByteArray> = emptyList(),
    ): HandshakeState = HandshakeState(this, initiator, prologue, localStatic, remoteStatic, psks)
}
