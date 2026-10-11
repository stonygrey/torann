// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

/// A Noise cipher function (Noise §4.2).
protocol NoiseCipher: Sendable {
    var name: String { get }
    func createKey(_ key: [UInt8]) -> CipherKey
}

/// An AEAD key. Output is ciphertext followed by the 16-byte tag.
protocol CipherKey: AnyObject {
    func encrypt(nonce: UInt64, ad: [UInt8], plaintext: [UInt8]) throws -> [UInt8]
    func decrypt(nonce: UInt64, ad: [UInt8], ciphertext: [UInt8]) throws -> [UInt8]
    func close()
}

enum CipherKeyMessages {
    static let tagMismatch = "The authentication tag did not match."
}
