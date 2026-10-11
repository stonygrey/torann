// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import Foundation

/// The result of `HandshakeState.writeMessage`. `handshakeHash` and `transport` are
/// present on the final message of the pattern only.
public struct HandshakeWriteResult: Sendable {
    public let message: Data
    public let handshakeHash: Data?
    public let transport: Transport?
}

/// The result of `HandshakeState.readMessage`. `handshakeHash` and `transport` are
/// present on the final message of the pattern only.
public struct HandshakeReadResult: Sendable {
    public let payload: Data
    public let handshakeHash: Data?
    public let transport: Transport?
}
