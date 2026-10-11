// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import Foundation
import Synchronization

/// A DH key pair. Create one with `NoiseProtocol.generateKeyPair()` or
/// `NoiseProtocol.createKeyPair(privateKey:)`. Every read returns a copy.
public final class KeyPair: Sendable {
    private struct State {
        var privateKey: [UInt8]?
        let publicKey: [UInt8]
        var closed = false
    }

    private let state: Mutex<State>

    init(privateKey: [UInt8], publicKey: [UInt8]) {
        state = Mutex(State(privateKey: privateKey, publicKey: publicKey))
    }

    /// The private key bytes. Raises `TorannError.closed` after `close()`.
    public var privateKey: Data {
        get throws { Data(try copyPrivateKey()) }
    }

    /// The public key bytes. Raises `TorannError.closed` after `close()`.
    public var publicKey: Data {
        get throws { Data(try copyPublicKey()) }
    }

    func copyPrivateKey() throws -> [UInt8] {
        try state.withLock { state in
            guard !state.closed, let key = state.privateKey else { throw TorannError.closed }
            return key
        }
    }

    func copyPublicKey() throws -> [UInt8] {
        try state.withLock { state in
            guard !state.closed else { throw TorannError.closed }
            return state.publicKey
        }
    }

    /// Zeros the private key. Reading either key afterwards raises `TorannError.closed`.
    public func close() {
        state.withLock { state in
            if state.closed { return }
            state.closed = true
            wipe(&state.privateKey)
        }
    }

    deinit {
        close()
    }
}
