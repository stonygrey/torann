// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

/// The HKDF variant of Noise §4.3: two or three full-hash-length outputs and no
/// info parameter. It is not RFC 5869 HKDF.
enum NoiseHkdf {
    static func derive(_ hash: NoiseHash, chainingKey: [UInt8], inputKeyMaterial: [UInt8], outputs: Int)
        -> (out1: [UInt8], out2: [UInt8], out3: [UInt8]) {
        var tempKey = hash.hmac(key: chainingKey, inputKeyMaterial, [])
        let out1 = hash.hmac(key: tempKey, [0x01], [])
        let out2 = hash.hmac(key: tempKey, out1, [0x02])
        let out3 = outputs == 3 ? hash.hmac(key: tempKey, out2, [0x03]) : []
        wipe(&tempKey)
        return (out1, out2, out3)
    }
}
