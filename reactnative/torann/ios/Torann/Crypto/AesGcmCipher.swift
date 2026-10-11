// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import CryptoKit
import Foundation

/// AES-256-GCM per Noise §12.4: the 12-byte nonce is 4 zero bytes followed by the
/// 64-bit counter in big-endian order.
struct AesGcmCipher: NoiseCipher {
    let name = "AESGCM"

    func createKey(_ key: [UInt8]) -> CipherKey { Key(key) }

    static func nonceBytes(_ n: UInt64) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 12)
        var counter = n.bigEndian
        withUnsafeBytes(of: &counter) { raw in
            for i in 0..<8 { bytes[4 + i] = raw[i] }
        }
        return bytes
    }

    final class Key: CipherKey {
        private var key: SymmetricKey?

        init(_ key: [UInt8]) { self.key = SymmetricKey(data: key) }

        func encrypt(nonce: UInt64, ad: [UInt8], plaintext: [UInt8]) throws -> [UInt8] {
            guard let key else { throw TorannError.closed }
            let n = try AES.GCM.Nonce(data: AesGcmCipher.nonceBytes(nonce))
            let box = try AES.GCM.seal(plaintext, using: key, nonce: n, authenticating: ad)
            return Array(box.ciphertext) + Array(box.tag)
        }

        func decrypt(nonce: UInt64, ad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8] {
            guard let key else { throw TorannError.closed }
            let n = try AES.GCM.Nonce(data: AesGcmCipher.nonceBytes(nonce))
            guard ciphertext.count >= 16 else {
                throw TorannError.authenticationFailed("Ciphertext is shorter than the authentication tag.")
            }
            let split = ciphertext.count - 16
            do {
                let box = try AES.GCM.SealedBox(nonce: n, ciphertext: ciphertext[..<split], tag: ciphertext[split...])
                return Array(try AES.GCM.open(box, using: key, authenticating: ad))
            } catch {
                throw TorannError.authenticationFailed(CipherKeyMessages.tagMismatch)
            }
        }

        func close() { key = nil }
    }
}
