// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann.testkit

import com.stonygrey.torann.HandshakeState
import com.stonygrey.torann.NoiseProtocol
import com.stonygrey.torann.TestCipherState
import com.stonygrey.torann.TorannException
import com.stonygrey.torann.TorannTestApi
import com.stonygrey.torann.Transport
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.security.SecureRandom

/** The JVM suite and the Android instrumented suite extend this class. */
@OptIn(TorannTestApi::class)
abstract class SecurityTests {
    private val random = SecureRandom()

    private fun randomBytes(count: Int) = ByteArray(count).also(random::nextBytes)

    private fun bytes(s: String) = s.toByteArray(Charsets.UTF_8)

    private inline fun <reified E : TorannException> assertThrows(expectedMessage: String? = null, block: () -> Unit): E {
        try {
            block()
        } catch (e: TorannException) {
            if (e !is E) fail("expected ${E::class.simpleName}, got ${e::class.simpleName}: ${e.message}")
            if (expectedMessage != null) assertEquals(expectedMessage, e.message)
            return e as E
        }
        fail("expected ${E::class.simpleName}")
        throw IllegalStateException()
    }

    private fun completeNn(): Pair<Transport, Transport> {
        val protocol = NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        val initiator = protocol.createHandshake(initiator = true)
        val responder = protocol.createHandshake(initiator = false)
        val m1 = initiator.writeMessage()
        responder.readMessage(m1.message)
        val m2 = responder.writeMessage()
        val r2 = initiator.readMessage(m2.message)
        initiator.close(); responder.close()
        return Pair(r2.transport!!, m2.transport!!)
    }

    @Test
    fun transportWriteAfterCloseThrows() {
        val (initiator, responder) = completeNn()
        initiator.close()
        assertThrows<TorannException.Closed> { initiator.writeMessage(bytes("secret!!")) }
        responder.close()
    }

    @Test
    fun transportReadAfterCloseThrows() {
        val (initiator, responder) = completeNn()
        val message = initiator.writeMessage(bytes("hello"))
        responder.close()
        assertThrows<TorannException.Closed> { responder.readMessage(message) }
        initiator.close()
    }

    @Test
    fun midHandshakeCloseThenWriteThrows() {
        val protocol = NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_SHA256")
        val initStatic = protocol.generateKeyPair()
        val respStatic = protocol.generateKeyPair()
        val initiator = protocol.createHandshake(initiator = true, localStatic = initStatic)
        val responder = protocol.createHandshake(initiator = false, localStatic = respStatic)

        responder.readMessage(initiator.writeMessage().message)
        initiator.readMessage(responder.writeMessage().message)

        initiator.close()
        assertThrows<TorannException.Closed> { initiator.writeMessage() }
        assertThrows<TorannException.Closed> { initiator.remoteStaticPublicKey }
        responder.close()
    }

    @Test
    fun tamperedHandshakeReadIsTerminal() {
        val protocol = NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_SHA256")
        val initStatic = protocol.generateKeyPair()
        val respStatic = protocol.generateKeyPair()
        val initiator = protocol.createHandshake(initiator = true, localStatic = initStatic)
        val responder = protocol.createHandshake(initiator = false, localStatic = respStatic)

        responder.readMessage(initiator.writeMessage().message)
        val good = responder.writeMessage().message
        val tampered = good.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0xFF).toByte()

        assertThrows<TorannException.AuthenticationFailed> { initiator.readMessage(tampered) }
        val retry = assertThrows<TorannException.InvalidState> { initiator.readMessage(good) }
        assertTrue(retry.message!!.lowercase().contains("failed"))
        assertNull(initiator.remoteStaticPublicKey)
        initiator.close(); responder.close()
    }

    @Test
    fun truncatedHandshakeMessageIsRejectedAndNotTerminal() {
        // The length check runs before the message pattern is consumed, so the handshake
        // stays usable.
        val protocol = NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        val initiator = protocol.createHandshake(initiator = true)
        val responder = protocol.createHandshake(initiator = false)
        val m1 = initiator.writeMessage().message
        assertThrows<TorannException.AuthenticationFailed>("The handshake message is truncated.") { responder.readMessage(m1.copyOf(10)) }
        responder.readMessage(m1)
        assertNotNull(responder.writeMessage().transport)
        initiator.close(); responder.close()
    }

    @Test
    fun oversizedHandshakePayloadDoesNotConsumeTheMessagePattern() {
        val protocol = NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        val initiator = protocol.createHandshake(initiator = true)
        val responder = protocol.createHandshake(initiator = false)
        assertThrows<TorannException.InvalidArgument>("A Noise message must not exceed 65535 bytes.") {
            initiator.writeMessage(ByteArray(70_000))
        }
        val written = initiator.writeMessage(bytes("hi"))
        assertArrayEquals(bytes("hi"), responder.readMessage(written.message).payload)
        initiator.close(); responder.close()
    }

    @Test
    fun createHandshakeRejectsMissingStaticAndPsk() {
        val xx = NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_SHA256")
        assertThrows<TorannException.InvalidArgument>("A local static key is required by the handshake pattern.") { xx.createHandshake(initiator = true) }

        val xxpsk3 = NoiseProtocol.parse("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
        val s = xxpsk3.generateKeyPair()
        assertThrows<TorannException.InvalidArgument>("The protocol requires 1 pre-shared key(s); 0 were provided.") {
            xxpsk3.createHandshake(initiator = true, localStatic = s)
        }
        assertThrows<TorannException.InvalidArgument>("Pre-shared keys must be 32 bytes.") {
            xxpsk3.createHandshake(initiator = true, localStatic = s, psks = listOf(ByteArray(31)))
        }

        val nk = NoiseProtocol.parse("Noise_NK_25519_ChaChaPoly_SHA256")
        val nkStatic = nk.generateKeyPair()
        assertThrows<TorannException.InvalidArgument>("The remote static public key is required by the handshake pattern.") {
            nk.createHandshake(initiator = true, localStatic = nkStatic)
        }
        assertThrows<TorannException.InvalidArgument>("Remote static public key must be 32 bytes.") {
            nk.createHandshake(initiator = true, remoteStatic = ByteArray(31))
        }

        nkStatic.close()
        assertThrows<TorannException.Closed> { xx.createHandshake(initiator = true, localStatic = nkStatic) }
    }

    @Test
    fun keyPairReturnsCopiesAndThrowsAfterClose() {
        for ((name, length) in listOf("Noise_NN_25519_ChaChaPoly_SHA256" to 32, "Noise_NN_448_ChaChaPoly_SHA256" to 56)) {
            val protocol = NoiseProtocol.parse(name)
            val keys = protocol.generateKeyPair()
            val copy = keys.privateKey
            val original = copy[0]
            copy[0] = (copy[0].toInt() xor 0xFF).toByte()
            assertEquals(original, keys.privateKey[0])
            assertEquals(length, keys.publicKey.size)

            val rebuilt = protocol.createKeyPair(keys.privateKey)
            assertArrayEquals(keys.publicKey, rebuilt.publicKey)
            assertThrows<TorannException.InvalidArgument>("The private key must be $length bytes.") { protocol.createKeyPair(ByteArray(length - 1)) }

            keys.close()
            assertThrows<TorannException.Closed> { keys.privateKey }
            assertThrows<TorannException.Closed> { keys.publicKey }
            keys.close()
            rebuilt.close()
        }
    }

    @Test
    fun rekeyRotatesTransportKeysWithoutResettingNonces() {
        val (initiator, responder) = completeNn()
        val first = initiator.writeMessage(bytes("one"))
        assertArrayEquals(bytes("one"), responder.readMessage(first))

        initiator.rekeySend()
        val second = initiator.writeMessage(bytes("two"))
        assertThrows<TorannException.AuthenticationFailed> { responder.readMessage(second) }

        responder.rekeyReceive()
        assertArrayEquals(bytes("two"), responder.readMessage(second))
        initiator.close(); responder.close()
    }

    @Test
    fun setReceiveNonceAllowsReplayOfAPreviousCiphertext() {
        val (initiator, responder) = completeNn()
        val saved = initiator.writeMessage(bytes("ping"))
        responder.readMessage(saved)
        responder.setReceiveNonce(0u)
        assertArrayEquals(bytes("ping"), responder.readMessage(saved))
        assertThrows<TorannException.InvalidArgument>("Nonce 2^64-1 is reserved.") { responder.setReceiveNonce(ULong.MAX_VALUE) }
        initiator.close(); responder.close()
    }

    @Test
    fun nonceExhaustionIsAnInvalidStateError() {
        val (initiator, responder) = completeNn()
        initiator.setSendNonce(ULong.MAX_VALUE - 1u)
        initiator.writeMessage(bytes("last"))
        assertThrows<TorannException.InvalidState>("Nonce exhausted; the session must be re-established.") { initiator.writeMessage(bytes("none")) }
        initiator.close(); responder.close()
    }

    @Test
    fun remoteStaticPublicKeyIsAvailableAfterSuccessfulXxMessage2() {
        val protocol = NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_SHA256")
        val initStatic = protocol.generateKeyPair()
        val respStatic = protocol.generateKeyPair()
        val initiator = protocol.createHandshake(initiator = true, localStatic = initStatic)
        val responder = protocol.createHandshake(initiator = false, localStatic = respStatic)

        responder.readMessage(initiator.writeMessage().message)
        assertNull(initiator.remoteStaticPublicKey)
        initiator.readMessage(responder.writeMessage().message)
        assertArrayEquals(respStatic.publicKey, initiator.remoteStaticPublicKey)

        // A key supplied up front is available at once.
        val nk = NoiseProtocol.parse("Noise_NK_25519_ChaChaPoly_SHA256")
        val nkInit = nk.createHandshake(initiator = true, remoteStatic = respStatic.publicKey)
        assertArrayEquals(respStatic.publicKey, nkInit.remoteStaticPublicKey)
        nkInit.close(); initiator.close(); responder.close()
    }

    @Test
    fun oneWayTransportRejectsTheReverseDirection() {
        val protocol = NoiseProtocol.parse("Noise_N_25519_AESGCM_SHA256")
        val respStatic = protocol.generateKeyPair()
        val initiator = protocol.createHandshake(initiator = true, remoteStatic = respStatic.publicKey)
        val responder = protocol.createHandshake(initiator = false, localStatic = respStatic)

        val written = initiator.writeMessage()
        val read = responder.readMessage(written.message)
        val initTransport = written.transport!!
        val respTransport = read.transport!!

        val message = initTransport.writeMessage(bytes("one way"))
        assertArrayEquals(bytes("one way"), respTransport.readMessage(message))

        val responderSends = "A one-way pattern's responder cannot send transport messages."
        val initiatorReceives = "A one-way pattern's initiator cannot receive transport messages."
        assertThrows<TorannException.InvalidState>(responderSends) { respTransport.writeMessage(bytes("nope")) }
        assertThrows<TorannException.InvalidState>(responderSends) { respTransport.rekeySend() }
        assertThrows<TorannException.InvalidState>(responderSends) { respTransport.setSendNonce(1u) }
        assertThrows<TorannException.InvalidState>(initiatorReceives) { initTransport.readMessage(message) }
        assertThrows<TorannException.InvalidState>(initiatorReceives) { initTransport.rekeyReceive() }
        assertThrows<TorannException.InvalidState>(initiatorReceives) { initTransport.setReceiveNonce(1u) }
        initTransport.close(); respTransport.close(); initiator.close(); responder.close()
    }

    @Test
    fun handshakeTurnAndCompletionErrors() {
        val protocol = NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        val initiator = protocol.createHandshake(initiator = true)
        val responder = protocol.createHandshake(initiator = false)

        assertThrows<TorannException.InvalidState>("It is not this party's turn to write a message.") { responder.writeMessage() }
        assertThrows<TorannException.InvalidState>("It is not this party's turn to read a message.") { initiator.readMessage(ByteArray(32)) }

        responder.readMessage(initiator.writeMessage().message)
        val m2 = responder.writeMessage()
        initiator.readMessage(m2.message)
        assertThrows<TorannException.InvalidState>("The handshake is already complete.") { initiator.writeMessage() }
        assertThrows<TorannException.InvalidState>("The handshake is already complete.") { responder.readMessage(m2.message) }
        m2.transport?.close(); initiator.close(); responder.close()
    }

    @Test
    fun lowOrderPeerKeyIsATerminalHandshakeFailure() {
        // NN message 1 carries only `e`; the first DH (`ee`) happens when the responder
        // writes message 2, so the responder's write fails and becomes terminal.
        for (name in listOf("Noise_NN_25519_ChaChaPoly_SHA256", "Noise_NN_448_ChaChaPoly_SHA256")) {
            val protocol = NoiseProtocol.parse(name)
            val initiator = protocol.createHandshake(initiator = true)
            val responder = protocol.createHandshake(initiator = false)
            val m1 = initiator.writeMessage().message
            val dhLen = if (name.contains("448")) 56 else 32
            for (i in 0 until dhLen) m1[i] = 0
            responder.readMessage(m1)
            assertThrows<TorannException.AuthenticationFailed>("The peer's public key is invalid.") { responder.writeMessage() }
            val retry = assertThrows<TorannException.InvalidState> { responder.writeMessage() }
            assertTrue(retry.message!!.contains("failed"))
            initiator.close(); responder.close()
        }
    }

    @Test
    fun parserReportsTheFirstUnsupportedPart() {
        assertThrows<TorannException.UnsupportedFunction>("Cipher function 'AESCBC' is not supported.") { NoiseProtocol.parse("Noise_XX_25519_AESCBC_SHA256") }
        assertThrows<TorannException.UnsupportedFunction>("Hash function 'SHA3' is not supported.") { NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_SHA3") }
        assertThrows<TorannException.UnsupportedFunction>("DH function '1024' is not supported.") { NoiseProtocol.parse("Noise_XX_1024_ChaChaPoly_SHA256") }
        assertThrows<TorannException.UnsupportedFunction>("Handshake pattern 'ZZ' is not supported.") { NoiseProtocol.parse("Noise_ZZ_25519_ChaChaPoly_SHA256") }
        assertThrows<TorannException.UnsupportedFunction>("Pattern modifier 'fallback' is not supported.") { NoiseProtocol.parse("Noise_XXfallback_25519_ChaChaPoly_SHA256") }
        assertThrows<TorannException.UnsupportedFunction>("Pattern modifier 'psk' is not supported.") { NoiseProtocol.parse("Noise_XXpsk+1_25519_ChaChaPoly_SHA256") }
        assertThrows<TorannException.UnsupportedFunction>("psk4 is out of range for pattern XX.") { NoiseProtocol.parse("Noise_XXpsk4_25519_ChaChaPoly_SHA256") }
        assertThrows<TorannException.InvalidProtocolName>("'Noise_XX_25519_ChaChaPoly' is not a valid Noise protocol name.") { NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly") }
        assertThrows<TorannException.InvalidProtocolName>("'' is not a valid Noise protocol name.") { NoiseProtocol.parse("") }
        for (name in listOf("Noise_XX_448_ChaChaPoly_SHA256", "Noise_XX_25519_ChaChaPoly_BLAKE2s", "Noise_IK_448_AESGCM_BLAKE2b", "Noise_NXpsk0+psk1+psk2_25519_AESGCM_SHA512")) {
            assertEquals(name, NoiseProtocol.parse(name).name)
        }
    }

    @Test
    fun setFixedEphemeralRejectsAClosedHandshakeAndAWrongLength() {
        val protocol = NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        val handshake = protocol.createHandshake(initiator = true)
        assertThrows<TorannException.InvalidArgument>("The private key must be 32 bytes.") { handshake.setFixedEphemeral(ByteArray(31)) }
        handshake.close()
        assertThrows<TorannException.Closed> { handshake.setFixedEphemeral(ByteArray(32)) }
    }

    @Test
    fun testCipherStateCopiesItsKeyAndRejectsAWrongLength() {
        // The wrapper owns a copy, so the caller's array is untouched.
        val key = ByteArray(32) { it.toByte() }
        val state = TestCipherState("AESGCM", key)
        assertArrayEquals(ByteArray(32) { it.toByte() }, key)
        assertEquals(16 + 3, state.encryptWithAd(ByteArray(0), bytes("abc")).size)
        state.close()
        assertThrows<TorannException.InvalidArgument>("The cipher key must be 32 bytes.") { TestCipherState("ChaChaPoly", ByteArray(31)) }
        assertThrows<TorannException.InvalidArgument>("The cipher key must be 32 bytes.") { TestCipherState.aeadEncrypt("AESGCM", ByteArray(16), 0u, ByteArray(0), ByteArray(0)) }
    }

    @Test
    fun keyDerivationMatchesRfc7748() {
        // RFC 7748 §6.1 and §6.2: Alice's and Bob's private keys derive the published public
        // keys. The shared secret is not checked here because the DH function is internal
        // to the library module.
        val cases = listOf(
            Triple("Noise_NN_25519_ChaChaPoly_SHA256",
                "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a" to "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb" to "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
            Triple("Noise_NN_448_ChaChaPoly_SHA256",
                "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b" to "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0",
                "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d" to "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"),
        )
        for ((name, alice, bob) in cases) {
            val protocol = NoiseProtocol.parse(name)
            for ((privateKey, publicKey) in listOf(alice, bob)) {
                val keys = protocol.createKeyPair(hexToBytes(privateKey))
                assertEquals(name, publicKey, bytesToHex(keys.publicKey))
                keys.close()
            }
        }
    }

    @Test
    fun rekeyMatchesTheSpecDefinition() {
        // No reference suite carries rekey vectors, so this encodes the definition
        // directly: REKEY(k) = ENCRYPT(k, 2^64-1, empty, zeros[32])[..32], nonce preserved.
        for (cipher in listOf("AESGCM", "ChaChaPoly")) {
            val key = randomBytes(32)
            val rekeyed = TestCipherState.aeadEncrypt(cipher, key, ULong.MAX_VALUE, ByteArray(0), ByteArray(32))
            val expected = TestCipherState.aeadEncrypt(cipher, rekeyed.copyOf(32), 5u, ByteArray(0), bytes("handshake!"))

            val state = TestCipherState(cipher, key)
            state.setNonce(5u)
            state.rekey()
            val actual = state.encryptWithAd(ByteArray(0), bytes("handshake!"))
            assertArrayEquals(cipher, expected, actual)
            state.close()
        }
    }

    @Test
    fun roundTripWithRandomKeysAcrossSupportedProtocols() {
        val names = listOf(
            "Noise_NN_25519_ChaChaPoly_SHA256",
            "Noise_XX_25519_ChaChaPoly_SHA256",
            "Noise_IK_25519_AESGCM_SHA512",
            "Noise_KK_25519_ChaChaPoly_SHA512",
            "Noise_NK_25519_AESGCM_SHA256",
            "Noise_XXpsk3_25519_ChaChaPoly_SHA256",
            "Noise_XX_448_ChaChaPoly_BLAKE2s",
            "Noise_IK_448_AESGCM_BLAKE2b",
        )
        for (name in names) {
            val protocol = NoiseProtocol.parse(name)
            val initStatic = protocol.generateKeyPair()
            val respStatic = protocol.generateKeyPair()
            val psks = if (name.contains("psk")) listOf(randomBytes(32)) else emptyList()
            val needsRemote = name.contains("_NK") || name.contains("_KK") || name.contains("_IK")

            val initiator = protocol.createHandshake(true, bytes("torann"), initStatic, if (needsRemote) respStatic.publicKey else null, psks)
            val responder = protocol.createHandshake(false, bytes("torann"), respStatic, if (name.contains("_KK")) initStatic.publicKey else null, psks)

            var writer: HandshakeState = initiator
            var reader: HandshakeState = responder
            var initTransport: Transport? = null
            var respTransport: Transport? = null
            while (initTransport == null) {
                val written = writer.writeMessage(bytes("ping"))
                val read = reader.readMessage(written.message)
                assertArrayEquals(name, bytes("ping"), read.payload)
                if (written.transport != null) {
                    initTransport = if (writer === initiator) written.transport else read.transport
                    respTransport = if (writer === initiator) read.transport else written.transport
                }
                val t = writer; writer = reader; reader = t
            }

            val data = randomBytes(1024)
            assertArrayEquals(name, data, respTransport!!.readMessage(initTransport.writeMessage(data)))
            assertArrayEquals(name, data, initTransport.readMessage(respTransport.writeMessage(data)))
            initTransport.close(); respTransport.close(); initiator.close(); responder.close(); initStatic.close(); respStatic.close()
        }
    }

    @Test
    fun tamperedTransportMessageThrows() {
        val (initiator, responder) = completeNn()
        val message = initiator.writeMessage(bytes("secret"))
        message[2] = (message[2].toInt() xor 0xFF).toByte()
        assertThrows<TorannException.AuthenticationFailed> { responder.readMessage(message) }
        // A failed decrypt leaves the transport usable and its nonce unchanged.
        message[2] = (message[2].toInt() xor 0xFF).toByte()
        assertArrayEquals(bytes("secret"), responder.readMessage(message))
        assertThrows<TorannException.AuthenticationFailed>("Ciphertext is shorter than the authentication tag.") { responder.readMessage(ByteArray(15)) }
        assertThrows<TorannException.InvalidArgument>("The payload must not exceed 65519 bytes.") { initiator.writeMessage(ByteArray(65520)) }
        assertThrows<TorannException.InvalidArgument>("A Noise message must not exceed 65535 bytes.") { responder.readMessage(ByteArray(65536)) }
        initiator.close(); responder.close()
    }
}
