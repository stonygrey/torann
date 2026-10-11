// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

/**
 * Post-handshake transport state: one send and one receive CipherState (Noise §5).
 * Messages carry a 16-byte authentication tag. Every public method runs under one
 * lock, so concurrent calls on one transport are serialized. A lost or reordered
 * message still desynchronizes the nonces, and the application discards the transport
 * after a decrypt failure.
 */
class Transport internal constructor(initiator: Boolean, c1: CipherState, c2: CipherState, oneWay: Boolean) : AutoCloseable {
    companion object {
        /** Size in bytes of the AEAD authentication tag appended to every transport message. */
        const val TAG_SIZE = 16
    }

    private val lock = Any()
    private val sendState: CipherState?
    private val receiveState: CipherState?
    private var closed = false

    init {
        if (oneWay) {
            // One-way patterns (Noise §7.4) use only the first CipherState;
            // traffic flows initiator-to-responder only.
            sendState = if (initiator) c1 else null
            receiveState = if (initiator) null else c1
            c2.close()
        } else {
            sendState = if (initiator) c1 else c2
            receiveState = if (initiator) c2 else c1
        }
    }

    private fun send(): CipherState =
        sendState ?: throw TorannException.InvalidState("A one-way pattern's responder cannot send transport messages.")

    private fun receive(): CipherState =
        receiveState ?: throw TorannException.InvalidState("A one-way pattern's initiator cannot receive transport messages.")

    /** Encrypts a payload of at most 65519 bytes. Returns ciphertext followed by the tag. */
    fun writeMessage(payload: ByteArray): ByteArray = synchronized(lock) {
        throwIfClosed()
        if (payload.size > NoiseProtocol.MAX_MESSAGE_LENGTH - TAG_SIZE) {
            throw TorannException.InvalidArgument("The payload must not exceed ${NoiseProtocol.MAX_MESSAGE_LENGTH - TAG_SIZE} bytes.")
        }
        send().encryptWithAd(ByteArray(0), payload)
    }

    /** Decrypts and authenticates a message. Returns the payload. */
    fun readMessage(message: ByteArray): ByteArray = synchronized(lock) {
        throwIfClosed()
        if (message.size > NoiseProtocol.MAX_MESSAGE_LENGTH) {
            throw TorannException.InvalidArgument("A Noise message must not exceed ${NoiseProtocol.MAX_MESSAGE_LENGTH} bytes.")
        }
        receive().decryptWithAd(ByteArray(0), message)
    }

    /** Rekeys the outgoing CipherState (Noise §11.3). Does not reset the nonce. */
    fun rekeySend() = synchronized(lock) {
        throwIfClosed()
        send().rekey()
    }

    /** Rekeys the incoming CipherState (Noise §11.3). Does not reset the nonce. */
    fun rekeyReceive() = synchronized(lock) {
        throwIfClosed()
        receive().rekey()
    }

    /** Sets the outgoing nonce. For out-of-order transport (Noise §11.4) only. `@JvmName` keeps the Java name readable despite the inline-class parameter. */
    @JvmName("setSendNonce")
    fun setSendNonce(nonce: ULong) = synchronized(lock) {
        throwIfClosed()
        send().setNonce(nonce)
    }

    /** Sets the incoming nonce. For out-of-order transport (Noise §11.4) only. */
    @JvmName("setReceiveNonce")
    fun setReceiveNonce(nonce: ULong) = synchronized(lock) {
        throwIfClosed()
        receive().setNonce(nonce)
    }

    private fun throwIfClosed() {
        if (closed) throw TorannException.Closed()
    }

    /** Closes both cipher states. Every operation afterwards raises [TorannException.Closed]. */
    override fun close() {
        synchronized(lock) {
            if (closed) return
            closed = true
            sendState?.close()
            receiveState?.close()
        }
    }
}
