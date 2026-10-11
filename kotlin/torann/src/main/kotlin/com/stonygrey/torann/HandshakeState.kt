// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

import java.io.ByteArrayOutputStream

/**
 * HandshakeState per Noise §5.3. Created with [NoiseProtocol.createHandshake]. Call
 * [writeMessage] and [readMessage] alternately; the final message returns a
 * [Transport]. A decrypt or DH failure after a message pattern is consumed is terminal:
 * the handshake refuses further use and must be discarded. Every public operation runs
 * under one lock.
 */
class HandshakeState internal constructor(
    protocol: NoiseProtocol,
    private val initiator: Boolean,
    prologue: ByteArray,
    localStatic: KeyPair?,
    remoteStatic: ByteArray?,
    psks: List<ByteArray>,
) : AutoCloseable {
    private val lock = Any()
    private val dh = protocol.dh
    private val oneWay = protocol.pattern.messages.size == 1
    private val hasPsk = protocol.pskCount > 0
    private val messagePatterns: ArrayDeque<List<Token>>
    private val psks: ArrayDeque<ByteArray>
    private val symmetric: SymmetricState
    private var turnToWrite = initiator
    private var finished = false
    private var failed = false
    private var closed = false

    private var sPrivate: ByteArray? = null
    private var sPublic: ByteArray? = null
    private var ePrivate: ByteArray? = null
    private var ePublic: ByteArray? = null
    private var rs: ByteArray? = null
    private var re: ByteArray? = null
    private var fixedEphemeral: ByteArray? = null

    init {
        for (psk in psks) {
            if (psk.size != 32) throw TorannException.InvalidArgument("Pre-shared keys must be 32 bytes.")
        }
        if (psks.size != protocol.pskCount) {
            throw TorannException.InvalidArgument(
                "The protocol requires ${protocol.pskCount} pre-shared key(s); ${psks.size} were provided.",
            )
        }

        val pattern = protocol.pattern
        val needsLocalStatic = if (initiator) pattern.initiatorSendsStatic else pattern.responderSendsStatic
        val needsRemoteStatic = if (initiator) pattern.hasResponderPreStatic else pattern.hasInitiatorPreStatic

        if (needsLocalStatic && localStatic == null) {
            throw TorannException.InvalidArgument("A local static key is required by the handshake pattern.")
        }
        if (needsRemoteStatic && remoteStatic == null) {
            throw TorannException.InvalidArgument("The remote static public key is required by the handshake pattern.")
        }

        // The key copies are made only after every check has passed, so a rejected call
        // leaves no unwiped copy behind.
        var staticPrivate: ByteArray? = null
        try {
            if (localStatic != null) {
                staticPrivate = localStatic.privateKey
                sPublic = localStatic.publicKey
            }
            if (remoteStatic != null && remoteStatic.size != dh.dhLen) {
                throw TorannException.InvalidArgument("Remote static public key must be ${dh.dhLen} bytes.")
            }
        } catch (e: Throwable) {
            staticPrivate?.wipe()
            throw e
        }
        sPrivate = staticPrivate
        rs = remoteStatic?.copyOf()
        this.psks = ArrayDeque(psks.map { it.copyOf() })

        messagePatterns = ArrayDeque(pattern.messages)
        symmetric = SymmetricState(protocol.name, protocol.cipher, protocol.hash)
        symmetric.mixHash(prologue)

        for (token in pattern.preInitiator) mixPreMessage(token, initiatorSide = true)
        for (token in pattern.preResponder) mixPreMessage(token, initiatorSide = false)
    }

    /**
     * The peer's static public key once known: at once when it was passed to
     * [NoiseProtocol.createHandshake], after the message that carried it otherwise. Null
     * after a terminal failure. Raises [TorannException.Closed] after [close].
     */
    val remoteStaticPublicKey: ByteArray?
        get() = synchronized(lock) {
            if (closed) throw TorannException.Closed()
            if (failed) null else rs?.copyOf()
        }

    /**
     * Test-only: the vector suites prescribe each party's ephemeral private key. Call it
     * before the message that carries this party's `e` token is written. `@JvmSynthetic`
     * hides it from Java callers; Kotlin callers still need the opt-in.
     */
    @TorannTestApi
    @JvmSynthetic
    fun setFixedEphemeral(privateKey: ByteArray) {
        synchronized(lock) {
            if (closed) throw TorannException.Closed()
            if (privateKey.size != dh.dhLen) {
                throw TorannException.InvalidArgument("The private key must be ${dh.dhLen} bytes.")
            }
            fixedEphemeral?.wipe()
            fixedEphemeral = privateKey.copyOf()
        }
    }

    /** Writes the next handshake message (Noise §5.3 WriteMessage). */
    @JvmOverloads
    fun writeMessage(payload: ByteArray = ByteArray(0)): HandshakeWriteResult = synchronized(lock) {
        throwIfUnavailable()
        if (!turnToWrite) {
            throw TorannException.InvalidState("It is not this party's turn to write a message.")
        }

        val tokens = messagePatterns.first()
        val (prefix, hasKey) = simulate(tokens)
        val overhead = prefix + (if (hasKey) Transport.TAG_SIZE else 0)
        // Compared this way round so that a huge payload cannot overflow the sum.
        if (payload.size > NoiseProtocol.MAX_MESSAGE_LENGTH - overhead) {
            throw TorannException.InvalidArgument("A Noise message must not exceed ${NoiseProtocol.MAX_MESSAGE_LENGTH} bytes.")
        }
        val size = overhead + payload.size

        try {
            messagePatterns.removeFirst()
            val message = ByteArrayOutputStream(size)
            for (token in tokens) {
                when (token) {
                    Token.E -> {
                        ePrivate?.wipe()
                        ePrivate = fixedEphemeral?.copyOf() ?: dh.generatePrivateKey()
                        val ePub = dh.derivePublicKey(ePrivate!!)
                        ePublic = ePub
                        message.write(ePub)
                        symmetric.mixHash(ePub)
                        if (hasPsk) symmetric.mixKey(ePub)
                    }
                    Token.S -> {
                        val sPub = sPublic ?: throw TorannException.InvalidState("A local static key is required.")
                        message.write(symmetric.encryptAndHash(sPub))
                    }
                    Token.PSK -> mixPsk()
                    else -> mixDh(token)
                }
            }

            message.write(symmetric.encryptAndHash(payload))
            turnToWrite = false
            val (hash, transport) = finish()
            HandshakeWriteResult(message.toByteArray(), hash, transport)
        } catch (e: Throwable) {
            // Throwable, not Exception: a JVM Error after the pattern is consumed must also
            // leave the handshake failed.
            failed = true
            throw e
        }
    }

    /** Reads the next handshake message from the peer (Noise §5.3 ReadMessage). */
    fun readMessage(message: ByteArray): HandshakeReadResult = synchronized(lock) {
        throwIfUnavailable()
        if (turnToWrite) {
            throw TorannException.InvalidState("It is not this party's turn to read a message.")
        }
        if (message.size > NoiseProtocol.MAX_MESSAGE_LENGTH) {
            throw TorannException.InvalidArgument("A Noise message must not exceed ${NoiseProtocol.MAX_MESSAGE_LENGTH} bytes.")
        }

        val tokens = messagePatterns.first()
        val (prefix, hasKey) = simulate(tokens)
        val minLength = prefix + (if (hasKey) Transport.TAG_SIZE else 0)
        if (message.size < minLength) {
            throw TorannException.AuthenticationFailed("The handshake message is truncated.")
        }

        try {
            messagePatterns.removeFirst()
            var offset = 0
            for (token in tokens) {
                when (token) {
                    Token.E -> {
                        requireLength(offset + dh.dhLen <= message.size)
                        val rePublic = message.copyOfRange(offset, offset + dh.dhLen)
                        offset += dh.dhLen
                        re = rePublic
                        symmetric.mixHash(rePublic)
                        if (hasPsk) symmetric.mixKey(rePublic)
                    }
                    Token.S -> {
                        val length = dh.dhLen + (if (symmetric.cipherHasKey) Transport.TAG_SIZE else 0)
                        requireLength(offset + length <= message.size)
                        rs = symmetric.decryptAndHash(message.copyOfRange(offset, offset + length))
                        offset += length
                    }
                    Token.PSK -> mixPsk()
                    else -> mixDh(token)
                }
            }

            requireLength(offset <= message.size)
            val payload = symmetric.decryptAndHash(message.copyOfRange(offset, message.size))
            turnToWrite = true
            val (hash, transport) = finish()
            HandshakeReadResult(payload, hash, transport)
        } catch (e: Throwable) {
            failed = true
            throw e
        }
    }

    private fun finish(): Pair<ByteArray?, Transport?> {
        if (messagePatterns.isNotEmpty()) return Pair(null, null)
        finished = true
        val handshakeHash = symmetric.handshakeHash
        val (c1, c2) = symmetric.split()
        clearHandshakeSecrets()
        return Pair(handshakeHash, Transport(initiator, c1, c2, oneWay))
    }

    /**
     * The minimum-length check before the token loop makes these guards redundant; they
     * keep a mismatch between [simulate] and the loop a Torann error rather than an
     * [IndexOutOfBoundsException].
     */
    private fun requireLength(condition: Boolean) {
        if (!condition) throw TorannException.AuthenticationFailed("The handshake message is truncated.")
    }

    private fun clearHandshakeSecrets() {
        symmetric.clearSecrets()
        sPrivate?.wipe(); sPrivate = null
        ePrivate?.wipe(); ePrivate = null
        fixedEphemeral?.wipe(); fixedEphemeral = null
        while (psks.isNotEmpty()) psks.removeFirst().wipe()
    }

    /**
     * Returns the byte length of the token prefix and whether a cipher key exists after
     * the tokens, which decides whether the payload carries a tag.
     */
    private fun simulate(tokens: List<Token>): Pair<Int, Boolean> {
        var size = 0
        var hasKey = symmetric.cipherHasKey
        for (token in tokens) {
            when (token) {
                Token.E -> {
                    size += dh.dhLen
                    if (hasPsk) hasKey = true
                }
                Token.S -> size += dh.dhLen + (if (hasKey) Transport.TAG_SIZE else 0)
                Token.PSK -> hasKey = true
                else -> hasKey = true
            }
        }
        return Pair(size, hasKey)
    }

    private fun mixPreMessage(token: Token, initiatorSide: Boolean) {
        if (token != Token.S) {
            throw TorannException.UnsupportedFunction("Only 's' pre-message tokens are supported.")
        }
        val key = if (initiatorSide == initiator) sPublic else rs
        symmetric.mixHash(
            key ?: throw TorannException.InvalidState("A static key required by the handshake pattern's pre-messages is missing."),
        )
    }

    private fun mixPsk() {
        if (psks.isEmpty()) {
            throw TorannException.InvalidState("The handshake pattern requires a pre-shared key that was not provided.")
        }
        val psk = psks.removeFirst()
        symmetric.mixKeyAndHash(psk)
        psk.wipe()
    }

    private fun mixDh(token: Token) {
        val (privateKey, publicKey) = when (token) {
            Token.EE -> Pair(ePrivate, re)
            Token.SS -> Pair(sPrivate, rs)
            Token.ES -> if (initiator) Pair(ePrivate, rs) else Pair(sPrivate, re)
            Token.SE -> if (initiator) Pair(sPrivate, re) else Pair(ePrivate, rs)
            else -> throw TorannException.InvalidState("Unexpected token $token.")
        }
        if (privateKey == null || publicKey == null) {
            throw TorannException.InvalidState("Key material for the '$token' token is missing.")
        }
        val shared = dh.dh(privateKey, publicKey)
        symmetric.mixKey(shared)
        shared.wipe()
    }

    private fun throwIfUnavailable() {
        if (closed) throw TorannException.Closed()
        if (failed) throw TorannException.InvalidState("The handshake has failed and must be discarded.")
        if (finished) throw TorannException.InvalidState("The handshake is already complete.")
    }

    /** Zeros all key material. Every operation afterwards raises [TorannException.Closed]. */
    override fun close() {
        synchronized(lock) {
            if (closed) return
            closed = true
            failed = true
            symmetric.close()
            sPrivate?.wipe(); sPrivate = null
            ePrivate?.wipe(); ePrivate = null
            fixedEphemeral?.wipe(); fixedEphemeral = null
            while (psks.isNotEmpty()) psks.removeFirst().wipe()
        }
    }
}
