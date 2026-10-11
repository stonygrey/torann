// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import CryptoKit
import Foundation

/// X25519 through CryptoKit. CryptoKit clamps the scalar inside the operation and
/// returns the stored private key bytes unchanged from `rawRepresentation`, so
/// unclamped private keys such as the vectors' ephemerals derive the public keys
/// the vectors expect.
struct Curve25519Dh: NoiseDh {
    static let invalidPeerKey = "The peer's public key is invalid."

    let name = "25519"
    let dhLen = 32

    func generatePrivateKey() -> [UInt8] {
        Array(Curve25519.KeyAgreement.PrivateKey().rawRepresentation)
    }

    func derivePublicKey(privateKey: [UInt8]) throws -> [UInt8] {
        Array(try makeKey(privateKey).publicKey.rawRepresentation)
    }

    func dh(privateKey: [UInt8], publicKey: [UInt8]) throws -> [UInt8] {
        let key = try makeKey(privateKey)
        let peer: Curve25519.KeyAgreement.PublicKey
        do {
            peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: publicKey)
        } catch {
            throw TorannError.authenticationFailed(Self.invalidPeerKey)
        }

        // CryptoKit throws `underlyingCoreCryptoError(error: -7)` for every low-order
        // point, so the all-zero check below is unreachable today. It stays so that a
        // CryptoKit that returned the zero output instead would still fail the handshake.
        let shared: SharedSecret
        do {
            shared = try key.sharedSecretFromKeyAgreement(with: peer)
        } catch {
            throw TorannError.authenticationFailed(Self.invalidPeerKey)
        }

        let bytes = shared.withUnsafeBytes { Array($0) }
        if bytes.allSatisfy({ $0 == 0 }) {
            throw TorannError.authenticationFailed(Self.invalidPeerKey)
        }

        return bytes
    }

    private func makeKey(_ privateKey: [UInt8]) throws -> Curve25519.KeyAgreement.PrivateKey {
        do {
            return try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: privateKey)
        } catch {
            throw TorannError.invalidArgument("The private key must be \(dhLen) bytes.")
        }
    }
}
