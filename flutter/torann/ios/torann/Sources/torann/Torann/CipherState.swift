// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

/// CipherState per Noise §5.1: an AEAD key plus a 64-bit nonce counter.
/// Not thread-safe on its own; `HandshakeState` and `Transport` hold the lock.
final class CipherState {
    private let cipher: NoiseCipher
    private var key: CipherKey?
    private var nonce: UInt64 = 0
    private var closed = false

    init(_ cipher: NoiseCipher) { self.cipher = cipher }

    var hasKey: Bool { !closed && key != nil }

    /// Installs a key and zeros `keyBytes` in place. The parameter is `inout` so that the
    /// caller's uniquely owned array is the one wiped; a by-value copy would be zeroed
    /// through copy-on-write while the original survived.
    func initializeKey(_ keyBytes: inout [UInt8]) throws {
        try throwIfClosed()
        key?.close()
        key = cipher.createKey(keyBytes)
        wipe(&keyBytes)
        nonce = 0
    }

    func setNonce(_ value: UInt64) throws {
        try throwIfClosed()
        if value == UInt64.max {
            throw TorannError.invalidArgument("Nonce 2^64-1 is reserved.")
        }
        nonce = value
    }

    /// Rekey per Noise §11.3 / §4.2: k = ENCRYPT(k, 2^64-1, empty, zeros[32])[..32]. Does not reset n.
    func rekey() throws {
        try throwIfClosed()
        guard let current = key else {
            throw TorannError.invalidState("Cannot rekey an empty CipherState.")
        }
        var output = try current.encrypt(nonce: UInt64.max, ad: [], plaintext: [UInt8](repeating: 0, count: 32))
        var newKey = Array(output[..<32])
        wipe(&output)
        let n = nonce
        current.close()
        key = cipher.createKey(newKey)
        wipe(&newKey)
        nonce = n
    }

    func encryptWithAd(_ ad: [UInt8], _ plaintext: [UInt8]) throws -> [UInt8] {
        try throwIfClosed()
        guard let key else { return plaintext }
        try checkNonce()
        let ciphertext = try key.encrypt(nonce: nonce, ad: ad, plaintext: plaintext)
        nonce += 1
        return ciphertext
    }

    func decryptWithAd(_ ad: [UInt8], _ ciphertext: [UInt8]) throws -> [UInt8] {
        try throwIfClosed()
        guard let key else { return ciphertext }
        if ciphertext.count < 16 {
            throw TorannError.authenticationFailed("Ciphertext is shorter than the authentication tag.")
        }
        try checkNonce()
        let plaintext = try key.decrypt(nonce: nonce, ad: ad, ciphertext: ciphertext)
        nonce += 1
        return plaintext
    }

    private func checkNonce() throws {
        // 2^64 - 1 is reserved (Noise §5.1); rekey or a new session is required first.
        if nonce == UInt64.max {
            throw TorannError.invalidState("Nonce exhausted; the session must be re-established.")
        }
    }

    private func throwIfClosed() throws {
        if closed { throw TorannError.closed }
    }

    func close() {
        if closed { return }
        closed = true
        key?.close()
        key = nil
    }
}
