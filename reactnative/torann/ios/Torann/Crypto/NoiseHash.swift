// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import CryptoKit
import Foundation

/// A Noise hash function (Noise §4.3).
protocol NoiseHash: Sendable {
    var name: String { get }
    var hashLen: Int { get }
    var blockLen: Int { get }
    /// HASH(a || b)
    func hash(_ a: [UInt8], _ b: [UInt8]) -> [UInt8]
    /// HMAC-HASH(key, a || b)
    func hmac(key: [UInt8], _ a: [UInt8], _ b: [UInt8]) -> [UInt8]
}

struct Sha2Hash<H: CryptoKit.HashFunction>: NoiseHash {
    let name: String
    let hashLen: Int
    let blockLen: Int

    func hash(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var h = H()
        h.update(data: a)
        if !b.isEmpty { h.update(data: b) }
        return Array(h.finalize())
    }

    func hmac(key: [UInt8], _ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var mac = HMAC<H>(key: SymmetricKey(data: key))
        mac.update(data: a)
        if !b.isEmpty { mac.update(data: b) }
        return Array(mac.finalize())
    }
}

enum Hashes {
    static let sha256 = Sha2Hash<SHA256>(name: "SHA256", hashLen: 32, blockLen: 64)
    static let sha512 = Sha2Hash<SHA512>(name: "SHA512", hashLen: 64, blockLen: 128)
}
