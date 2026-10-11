// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// The Android side of the React Native package: the Kotlin implementation
// (com.stonygrey:torann) exposed to JavaScript through Expo's module API as three
// shared-object classes. sharedObjectDidRelease closes a native object that JavaScript
// released without calling close().

package com.stonygrey.torann.reactnative

import com.stonygrey.torann.HandshakeState
import com.stonygrey.torann.KeyPair
import com.stonygrey.torann.NoiseProtocol
import com.stonygrey.torann.TorannException
import com.stonygrey.torann.TorannTestApi
import com.stonygrey.torann.Transport
import expo.modules.kotlin.AppContext
import expo.modules.kotlin.exception.CodedException
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import expo.modules.kotlin.sharedobjects.SharedObject

class KeyPairObject(appContext: AppContext, val keys: KeyPair) : SharedObject(appContext) {
    override fun sharedObjectDidRelease() {
        keys.close()
        super.sharedObjectDidRelease()
    }
}

class HandshakeObject(appContext: AppContext, val handshake: HandshakeState) : SharedObject(appContext) {
    var handshakeHash: ByteArray? = null
    var transport: Transport? = null

    override fun sharedObjectDidRelease() {
        handshake.close()
        // A transport that JavaScript never took is closed with the handshake.
        transport?.close()
        super.sharedObjectDidRelease()
    }
}

class TransportObject(appContext: AppContext, val transport: Transport) : SharedObject(appContext) {
    override fun sharedObjectDidRelease() {
        transport.close()
        super.sharedObjectDidRelease()
    }
}

@OptIn(TorannTestApi::class)
class TorannModule : Module() {
    override fun definition() = ModuleDefinition {
        Name("Torann")

        Function("parseProtocol") { name: String -> wrap { NoiseProtocol.parse(name); Unit } }

        Function("generateKeyPair") { name: String ->
            wrap { KeyPairObject(appContext, NoiseProtocol.parse(name).generateKeyPair()) }
        }

        Function("createKeyPair") { name: String, privateKey: ByteArray ->
            wrap {
                try {
                    KeyPairObject(appContext, NoiseProtocol.parse(name).createKeyPair(privateKey))
                } finally {
                    // The library copies the array, so this module zeros the decoded one.
                    privateKey.fill(0)
                }
            }
        }

        Function("createHandshake") { name: String, initiator: Boolean, prologue: ByteArray, localStatic: KeyPairObject?, remoteStatic: ByteArray?, psks: List<ByteArray> ->
            wrap {
                try {
                    val handshake = NoiseProtocol.parse(name).createHandshake(initiator, prologue, localStatic?.keys, remoteStatic, psks)
                    HandshakeObject(appContext, handshake)
                } finally {
                    psks.forEach { it.fill(0) }
                }
            }
        }

        Class(KeyPairObject::class) {
            Constructor { notConstructible() }
            Function("publicKey") { ref: KeyPairObject -> wrap { ref.keys.publicKey } }
            Function("privateKey") { ref: KeyPairObject -> wrap { ref.keys.privateKey } }
            Function("close") { ref: KeyPairObject -> ref.keys.close() }
        }

        Class(HandshakeObject::class) {
            Constructor { notConstructible() }
            Function("writeMessage") { ref: HandshakeObject, payload: ByteArray ->
                wrap {
                    val result = ref.handshake.writeMessage(payload)
                    ref.handshakeHash = result.handshakeHash
                    ref.transport = result.transport
                    result.message
                }
            }
            Function("readMessage") { ref: HandshakeObject, message: ByteArray ->
                wrap {
                    val result = ref.handshake.readMessage(message)
                    ref.handshakeHash = result.handshakeHash
                    ref.transport = result.transport
                    result.payload
                }
            }
            Function("handshakeHash") { ref: HandshakeObject -> ref.handshakeHash }
            Function("takeTransport") { ref: HandshakeObject ->
                val transport = ref.transport ?: return@Function null
                ref.transport = null
                TransportObject(appContext, transport)
            }
            Function("remoteStaticPublicKey") { ref: HandshakeObject -> wrap { ref.handshake.remoteStaticPublicKey } }
            Function("close") { ref: HandshakeObject -> ref.handshake.close() }
            Function("setFixedEphemeral") { ref: HandshakeObject, privateKey: ByteArray ->
                wrap {
                    try {
                        ref.handshake.setFixedEphemeral(privateKey)
                    } finally {
                        privateKey.fill(0)
                    }
                }
            }
        }

        Class(TransportObject::class) {
            Constructor { notConstructible() }
            Function("writeMessage") { ref: TransportObject, payload: ByteArray -> wrap { ref.transport.writeMessage(payload) } }
            Function("readMessage") { ref: TransportObject, message: ByteArray -> wrap { ref.transport.readMessage(message) } }
            Function("rekeySend") { ref: TransportObject -> wrap { ref.transport.rekeySend() } }
            Function("rekeyReceive") { ref: TransportObject -> wrap { ref.transport.rekeyReceive() } }
            Function("setSendNonce") { ref: TransportObject, nonce: Double -> wrap { ref.transport.setSendNonce(nonceValue(nonce)) } }
            Function("setReceiveNonce") { ref: TransportObject, nonce: Double -> wrap { ref.transport.setReceiveNonce(nonceValue(nonce)) } }
            Function("close") { ref: TransportObject -> ref.transport.close() }
        }
    }

    /**
     * The Kotlin side of Expo requires a Constructor on every shared-object class; the
     * three classes here are created by the module's functions, never by JavaScript.
     */
    private fun notConstructible(): Nothing =
        throw CodedException("invalidState", "Torann objects are created by the module's functions, not by JavaScript.", null)

    /** JavaScript numbers arrive as doubles. */
    private fun nonceValue(nonce: Double): ULong {
        if (nonce < 0 || nonce != Math.floor(nonce) || nonce > 9007199254740991.0) {
            throw TorannException.InvalidArgument("The nonce must be an integer from 0 to 2^53 - 1.")
        }
        return nonce.toLong().toULong()
    }

    /**
     * A throwable other than a [TorannException] becomes `hostFailure` carrying only its
     * type name, so that no foreign message reaches JavaScript.
     */
    private inline fun <T> wrap(body: () -> T): T = try {
        body()
    } catch (e: TorannException) {
        throw CodedException(code(e), e.message, e)
    } catch (e: CodedException) {
        throw e
    } catch (e: Throwable) {
        throw CodedException("hostFailure", e.javaClass.simpleName, e)
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
