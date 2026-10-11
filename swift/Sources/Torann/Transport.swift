// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import Foundation
import Synchronization

/// Post-handshake transport state: one send and one receive CipherState (Noise §5).
/// Messages carry a 16-byte authentication tag. A lost or reordered message
/// desynchronizes the nonces, and the application discards the transport after a
/// decrypt failure.
public final class Transport: Sendable {
    /// Size in bytes of the AEAD authentication tag appended to every transport message.
    public static let tagSize = 16

    /// `@unchecked Sendable` because the two CipherStates are class instances that only
    /// this value references and that are reached only through the mutex; Swift's region
    /// analysis cannot see that they leave the handshake's region when `split()` hands
    /// them over.
    private struct State: @unchecked Sendable {
        let sendState: CipherState?
        let receiveState: CipherState?
        var closed = false

        func send() throws -> CipherState {
            guard let sendState else {
                throw TorannError.invalidState("A one-way pattern's responder cannot send transport messages.")
            }
            return sendState
        }

        func receive() throws -> CipherState {
            guard let receiveState else {
                throw TorannError.invalidState("A one-way pattern's initiator cannot receive transport messages.")
            }
            return receiveState
        }

        func throwIfClosed() throws {
            if closed { throw TorannError.closed }
        }
    }

    private let state: Mutex<State>

    init(initiator: Bool, c1: CipherState, c2: CipherState, oneWay: Bool) {
        if oneWay {
            // A one-way pattern (Noise §7.4) uses only the first CipherState.
            c2.close()
            state = Mutex(State(sendState: initiator ? c1 : nil, receiveState: initiator ? nil : c1))
        } else {
            state = Mutex(State(sendState: initiator ? c1 : c2, receiveState: initiator ? c2 : c1))
        }
    }

    /// Encrypts a payload of at most 65519 bytes. Returns ciphertext followed by the tag.
    public func writeMessage(payload: Data) throws -> Data {
        try state.withLock { state in
            try state.throwIfClosed()
            if payload.count > NoiseProtocol.maxMessageLength - Transport.tagSize {
                throw TorannError.invalidArgument(
                    "The payload must not exceed \(NoiseProtocol.maxMessageLength - Transport.tagSize) bytes.")
            }
            return Data(try state.send().encryptWithAd([], Array(payload)))
        }
    }

    /// Decrypts and authenticates a message. Returns the payload.
    public func readMessage(_ message: Data) throws -> Data {
        try state.withLock { state in
            try state.throwIfClosed()
            if message.count > NoiseProtocol.maxMessageLength {
                throw TorannError.invalidArgument("A Noise message must not exceed \(NoiseProtocol.maxMessageLength) bytes.")
            }
            return Data(try state.receive().decryptWithAd([], Array(message)))
        }
    }

    /// Rekeys the outgoing CipherState (Noise §11.3). Does not reset the nonce.
    public func rekeySend() throws {
        try state.withLock { state in
            try state.throwIfClosed()
            try state.send().rekey()
        }
    }

    /// Rekeys the incoming CipherState (Noise §11.3). Does not reset the nonce.
    public func rekeyReceive() throws {
        try state.withLock { state in
            try state.throwIfClosed()
            try state.receive().rekey()
        }
    }

    /// Sets the outgoing nonce. For out-of-order transport (Noise §11.4) only.
    public func setSendNonce(_ nonce: UInt64) throws {
        try state.withLock { state in
            try state.throwIfClosed()
            try state.send().setNonce(nonce)
        }
    }

    /// Sets the incoming nonce. For out-of-order transport (Noise §11.4) only.
    public func setReceiveNonce(_ nonce: UInt64) throws {
        try state.withLock { state in
            try state.throwIfClosed()
            try state.receive().setNonce(nonce)
        }
    }

    /// Closes both cipher states. Every operation afterwards raises `TorannError.closed`.
    public func close() {
        state.withLock { state in
            if state.closed { return }
            state.closed = true
            state.sendState?.close()
            state.receiveState?.close()
        }
    }

    deinit {
        close()
    }
}
