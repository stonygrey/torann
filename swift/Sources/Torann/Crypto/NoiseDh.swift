// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

/// A Noise DH function (Noise §4.1).
protocol NoiseDh: Sendable {
    var name: String { get }
    var dhLen: Int { get }
    func generatePrivateKey() -> [UInt8]
    func derivePublicKey(privateKey: [UInt8]) throws -> [UInt8]
    /// Raises `TorannError.authenticationFailed` when the output would be all zeros,
    /// which is terminal for the handshake.
    func dh(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8]
}
