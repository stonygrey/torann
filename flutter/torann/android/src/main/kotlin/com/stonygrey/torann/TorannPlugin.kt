// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// The Android side of the Flutter plugin. It implements the Pigeon host API over the
// Kotlin implementation (com.stonygrey:torann), keeps a table of open key pairs,
// handshakes, and transports named by integer handles, and contains no cryptography
// of its own.

package com.stonygrey.torann

import io.flutter.embedding.engine.plugins.FlutterPlugin

class TorannPlugin : FlutterPlugin {
    private var host: TorannHost? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        val created = TorannHost()
        host = created
        TorannHostApi.setUp(binding.binaryMessenger, created)
    }

    /**
     * Closes every open key pair, handshake, and transport when the engine detaches, so
     * that key material is wiped rather than left to the garbage collector.
     */
    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        host?.closeAll()
        host = null
        TorannHostApi.setUp(binding.binaryMessenger, null)
    }
}

@OptIn(TorannTestApi::class)
internal class TorannHost : TorannHostApi {
    private val lock = Any()
    private var nextHandle = 1L
    private var shutDown = false
    private val keyPairs = HashMap<Long, KeyPair>()
    private val handshakes = HashMap<Long, HandshakeState>()
    private val transports = HashMap<Long, Transport>()

    override fun parseProtocol(name: String) = wrap { NoiseProtocol.parse(name); Unit }

    override fun generateKeyPair(protocol: String): KeyPairMessage = wrap {
        val keys = NoiseProtocol.parse(protocol).generateKeyPair()
        KeyPairMessage(store(keyPairs, keys), keys.publicKey)
    }

    override fun createKeyPair(protocol: String, privateKey: ByteArray): KeyPairMessage = wrap {
        // The decoded array is the plugin's to zero; the library keeps its own copy.
        try {
            val keys = NoiseProtocol.parse(protocol).createKeyPair(privateKey)
            KeyPairMessage(store(keyPairs, keys), keys.publicKey)
        } finally {
            privateKey.fill(0)
        }
    }

    override fun keyPairPrivateKey(keyPair: Long): ByteArray = wrap { lookup(keyPairs, keyPair).privateKey }

    override fun closeKeyPair(keyPair: Long) {
        synchronized(lock) { keyPairs.remove(keyPair) }?.close()
    }

    override fun createHandshake(
        protocol: String, initiator: Boolean, prologue: ByteArray,
        localStatic: Long?, remoteStatic: ByteArray?, psks: List<ByteArray>,
    ): Long = wrap {
        try {
            val local = localStatic?.let { lookup(keyPairs, it) }
            val handshake = NoiseProtocol.parse(protocol).createHandshake(initiator, prologue, local, remoteStatic, psks)
            store(handshakes, handshake)
        } finally {
            psks.forEach { it.fill(0) }
        }
    }

    override fun handshakeWrite(handshake: Long, payload: ByteArray): HandshakeWriteMessage = wrap {
        val result = lookup(handshakes, handshake).writeMessage(payload)
        HandshakeWriteMessage(result.message, result.handshakeHash, result.transport?.let { store(transports, it) })
    }

    override fun handshakeRead(handshake: Long, message: ByteArray): HandshakeReadMessage = wrap {
        val result = lookup(handshakes, handshake).readMessage(message)
        HandshakeReadMessage(result.payload, result.handshakeHash, result.transport?.let { store(transports, it) })
    }

    override fun handshakeRemoteStaticPublicKey(handshake: Long): ByteArray? = wrap { lookup(handshakes, handshake).remoteStaticPublicKey }

    override fun closeHandshake(handshake: Long) {
        synchronized(lock) { handshakes.remove(handshake) }?.close()
    }

    override fun transportWrite(transport: Long, payload: ByteArray): ByteArray = wrap { lookup(transports, transport).writeMessage(payload) }

    override fun transportRead(transport: Long, message: ByteArray): ByteArray = wrap { lookup(transports, transport).readMessage(message) }

    override fun transportRekeySend(transport: Long) = wrap { lookup(transports, transport).rekeySend() }

    override fun transportRekeyReceive(transport: Long) = wrap { lookup(transports, transport).rekeyReceive() }

    override fun transportSetSendNonce(transport: Long, nonce: Long) = wrap { lookup(transports, transport).setSendNonce(nonceValue(nonce)) }

    override fun transportSetReceiveNonce(transport: Long, nonce: Long) = wrap { lookup(transports, transport).setReceiveNonce(nonceValue(nonce)) }

    override fun closeTransport(transport: Long) {
        synchronized(lock) { transports.remove(transport) }?.close()
    }

    override fun setFixedEphemeral(handshake: Long, privateKey: ByteArray) = wrap {
        try {
            lookup(handshakes, handshake).setFixedEphemeral(privateKey)
        } finally {
            privateKey.fill(0)
        }
    }

    /**
     * Host calls run on a serial background queue and this runs on the platform thread,
     * so a call can finish after the tables are emptied; [shutDown] makes its [store]
     * close the new object instead of keeping it.
     */
    fun closeAll() {
        val (keys, states, channels) = synchronized(lock) {
            shutDown = true
            Triple(keyPairs.values.toList(), handshakes.values.toList(), transports.values.toList()).also {
                keyPairs.clear(); handshakes.clear(); transports.clear()
            }
        }
        keys.forEach { it.close() }
        states.forEach { it.close() }
        channels.forEach { it.close() }
    }

    private fun <T : AutoCloseable> store(table: HashMap<Long, T>, value: T): Long = synchronized(lock) {
        if (shutDown) {
            value.close()
            throw TorannException.Closed()
        }
        val handle = nextHandle++
        table[handle] = value
        handle
    }

    private fun <T : Any> lookup(table: HashMap<Long, T>, handle: Long): T =
        synchronized(lock) { table[handle] } ?: throw TorannException.Closed()

    private fun nonceValue(nonce: Long): ULong {
        if (nonce < 0) throw TorannException.InvalidArgument("The nonce must not be negative.")
        return nonce.toULong()
    }

    /**
     * Runs one host call and converts a [TorannException] into a [FlutterError] whose
     * code is the shared error category, which the Dart layer maps back to a typed
     * exception.
     */
    private inline fun <T> wrap(body: () -> T): T = try {
        body()
    } catch (e: TorannException) {
        throw FlutterError(code(e), e.message, null)
    } catch (e: FlutterError) {
        throw e
    } catch (e: Throwable) {
        // Only the type name crosses the boundary, never the exception text.
        throw FlutterError("hostFailure", e.javaClass.simpleName, null)
    }

    private fun code(e: TorannException): String = when (e) {
        is TorannException.InvalidProtocolName -> "invalidProtocolName"
        is TorannException.UnsupportedFunction -> "unsupportedFunction"
        is TorannException.InvalidArgument -> "invalidArgument"
        is TorannException.InvalidState -> "invalidState"
        is TorannException.AuthenticationFailed -> "authenticationFailed"
        is TorannException.Closed -> "closed"
    }
}
