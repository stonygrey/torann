// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import Foundation

/// A parsed Noise protocol name such as `Noise_XX_25519_ChaChaPoly_SHA256`, and the
/// factory for key pairs and handshakes. Supports DH `25519`, ciphers `ChaChaPoly` and
/// `AESGCM`, and hashes `SHA256` and `SHA512`.
public final class NoiseProtocol: Sendable {
    /// Maximum length in bytes of a Noise handshake or transport message (Noise §3).
    public static let maxMessageLength = 65535

    /// The full protocol name, exactly as parsed.
    public let name: String

    let pattern: HandshakePattern
    let cipher: NoiseCipher
    let hash: NoiseHash
    let dh: NoiseDh
    let pskCount: Int

    private init(name: String, pattern: HandshakePattern, cipher: NoiseCipher, hash: NoiseHash, dh: NoiseDh, pskCount: Int) {
        self.name = name
        self.pattern = pattern
        self.cipher = cipher
        self.hash = hash
        self.dh = dh
        self.pskCount = pskCount
    }

    /// Parses `Noise_{pattern}{modifiers}_{dh}_{cipher}_{hash}`.
    public static func parse(_ name: String) throws -> NoiseProtocol {
        let parts = name.split(separator: "_", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 5, parts[0] == "Noise" else {
            throw TorannError.invalidProtocolName("'\(name)' is not a valid Noise protocol name.")
        }

        // Pattern names are upper-case ASCII letters plus the deferred-pattern digits
        // (NK1, X1X1); modifiers (psk0, ...) start with a lower-case letter.
        let patternPart = parts[1]
        let scalars = Array(patternPart.unicodeScalars)
        var split = 0
        while split < scalars.count, isUpperOrDigit(scalars[split]) {
            split += 1
        }
        let patternName = String(String.UnicodeScalarView(scalars[..<split]))
        guard var pattern = HandshakePattern.registry[patternName] else {
            throw TorannError.unsupportedFunction("Handshake pattern '\(patternName)' is not supported.")
        }

        var pskPositions: [Int] = []
        if split < scalars.count {
            let modifiers = String(String.UnicodeScalarView(scalars[split...]))
            for modifier in modifiers.split(separator: "+", omittingEmptySubsequences: false).map(String.init) {
                guard modifier.hasPrefix("psk"), let position = parsePskPosition(modifier.dropFirst(3)) else {
                    throw TorannError.unsupportedFunction("Pattern modifier '\(modifier)' is not supported.")
                }
                pskPositions.append(position)
            }
        }

        pattern = try pattern.withPsks(pskPositions)

        let dh: NoiseDh
        switch parts[2] {
        case "25519": dh = Curve25519Dh()
        default: throw TorannError.unsupportedFunction("DH function '\(parts[2])' is not supported.")
        }

        let cipher: NoiseCipher
        switch parts[3] {
        case "ChaChaPoly": cipher = ChaChaPolyCipher()
        case "AESGCM": cipher = AesGcmCipher()
        default: throw TorannError.unsupportedFunction("Cipher function '\(parts[3])' is not supported.")
        }

        let hash: NoiseHash
        switch parts[4] {
        case "SHA256": hash = Hashes.sha256
        case "SHA512": hash = Hashes.sha512
        default: throw TorannError.unsupportedFunction("Hash function '\(parts[4])' is not supported.")
        }

        return NoiseProtocol(name: name, pattern: pattern, cipher: cipher, hash: hash, dh: dh, pskCount: pskPositions.count)
    }

    private static func isUpperOrDigit(_ scalar: Unicode.Scalar) -> Bool {
        (scalar >= "A" && scalar <= "Z") || (scalar >= "0" && scalar <= "9")
    }

    private static func parsePskPosition(_ digits: Substring) -> Int? {
        guard !digits.isEmpty, digits.unicodeScalars.allSatisfy({ $0 >= "0" && $0 <= "9" }) else { return nil }
        return Int(digits)
    }

    /// Generates a fresh static key pair for this protocol's DH function.
    public func generateKeyPair() throws -> KeyPair {
        var privateKey = dh.generatePrivateKey()
        defer { wipe(&privateKey) }
        return try makeKeyPair(privateKey)
    }

    /// Reconstructs a key pair from a stored private key.
    public func createKeyPair(privateKey: Data) throws -> KeyPair {
        guard privateKey.count == dh.dhLen else {
            throw TorannError.invalidArgument("The private key must be \(dh.dhLen) bytes.")
        }
        var bytes = Array(privateKey)
        defer { wipe(&bytes) }
        return try makeKeyPair(bytes)
    }

    private func makeKeyPair(_ privateKey: [UInt8]) throws -> KeyPair {
        let publicKey = try dh.derivePublicKey(privateKey: privateKey)
        return KeyPair(privateKey: privateKey, publicKey: publicKey)
    }

    /// Creates a handshake. `initiator` is true for the party that sends the first
    /// message. `prologue` is authenticated but not transmitted. `localStatic` is
    /// required when the pattern sends or pre-shares this party's static key, and
    /// `remoteStatic` when it pre-shares the peer's. `psks` holds one 32-byte key per
    /// psk modifier, consumed in the order the `psk` tokens occur in the pattern. Every argument is copied.
    public func createHandshake(
        initiator: Bool,
        prologue: Data = Data(),
        localStatic: KeyPair? = nil,
        remoteStatic: Data? = nil,
        psks: [Data] = []
    ) throws -> HandshakeState {
        // The handshake takes ownership of these copies and wipes them if any check
        // fails; the caller's `Data` values are the caller's to clear.
        var pskCopies = psks.map { Array($0) }
        return try HandshakeState(
            protocol: self,
            initiator: initiator,
            prologue: Array(prologue),
            localStatic: localStatic,
            remoteStatic: remoteStatic.map { Array($0) },
            psks: &pskCopies)
    }
}
