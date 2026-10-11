// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

/// The errors Torann raises, one case per error category. No message contains key
/// material.
public enum TorannError: Error, Equatable, Sendable {
    /// The name is not `Noise_` followed by four parts.
    case invalidProtocolName(String)
    /// The pattern, modifier, DH, cipher, or hash is not supported.
    case unsupportedFunction(String)
    /// A length, count, or required argument is wrong. The object remains usable.
    case invalidArgument(String)
    /// Wrong turn, handshake complete or failed, one-way direction, or nonce exhausted.
    case invalidState(String)
    /// A message is truncated or its tag does not verify. During a handshake this is
    /// terminal once a message pattern has been consumed.
    case authenticationFailed(String)
    /// The object has been closed.
    case closed

    /// The message for logs.
    public var message: String {
        switch self {
        case .invalidProtocolName(let m), .unsupportedFunction(let m), .invalidArgument(let m),
             .invalidState(let m), .authenticationFailed(let m):
            return m
        case .closed:
            return "The object has been closed."
        }
    }
}
