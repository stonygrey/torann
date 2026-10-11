// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

/// SymmetricState per Noise §5.2: chaining key, handshake hash, and inner CipherState.
final class SymmetricState {
    private let hash: NoiseHash
    private let cipher: NoiseCipher
    private let cipherState: CipherState
    private var ck: [UInt8]
    private var h: [UInt8]

    init(protocolName: String, cipher: NoiseCipher, hash: NoiseHash) {
        self.hash = hash
        self.cipher = cipher
        cipherState = CipherState(cipher)
        let name = Array(protocolName.utf8)
        if name.count <= hash.hashLen {
            h = name + [UInt8](repeating: 0, count: hash.hashLen - name.count)
        } else {
            h = hash.hash(name, [])
        }
        ck = h
    }

    var cipherHasKey: Bool { cipherState.hasKey }

    func mixHash(_ data: [UInt8]) {
        h = hash.hash(h, data)
    }

    func mixKey(_ inputKeyMaterial: [UInt8]) throws {
        var (out1, out2, _) = NoiseHkdf.derive(hash, chainingKey: ck, inputKeyMaterial: inputKeyMaterial, outputs: 2)
        wipe(&ck)
        ck = out1
        var key = Array(out2[..<32])
        try cipherState.initializeKey(&key)
        wipe(&out2)
        wipe(&out1)
    }

    func mixKeyAndHash(_ inputKeyMaterial: [UInt8]) throws {
        var (out1, out2, out3) = NoiseHkdf.derive(hash, chainingKey: ck, inputKeyMaterial: inputKeyMaterial, outputs: 3)
        wipe(&ck)
        ck = out1
        mixHash(out2)
        var key = Array(out3[..<32])
        try cipherState.initializeKey(&key)
        wipe(&out1)
        wipe(&out2)
        wipe(&out3)
    }

    func encryptAndHash(_ plaintext: [UInt8]) throws -> [UInt8] {
        let ciphertext = try cipherState.encryptWithAd(h, plaintext)
        mixHash(ciphertext)
        return ciphertext
    }

    func decryptAndHash(_ ciphertext: [UInt8]) throws -> [UInt8] {
        let plaintext = try cipherState.decryptWithAd(h, ciphertext)
        mixHash(ciphertext)
        return plaintext
    }

    func split() throws -> (CipherState, CipherState) {
        var (out1, out2, _) = NoiseHkdf.derive(hash, chainingKey: ck, inputKeyMaterial: [], outputs: 2)
        var k1 = Array(out1[..<32])
        var k2 = Array(out2[..<32])
        let c1 = CipherState(cipher)
        try c1.initializeKey(&k1)
        let c2 = CipherState(cipher)
        try c2.initializeKey(&k2)
        wipe(&out1)
        wipe(&out2)
        return (c1, c2)
    }

    var handshakeHash: [UInt8] { h }

    /// Zeros ck and the handshake CipherState after Split, leaving h for channel binding.
    func clearSecrets() {
        cipherState.close()
        wipe(&ck)
    }

    func close() {
        cipherState.close()
        wipe(&ck)
    }
}
