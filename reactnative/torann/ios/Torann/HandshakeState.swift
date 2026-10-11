// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import Foundation
import Synchronization

/// HandshakeState per Noise §5.3. Created with `NoiseProtocol.createHandshake`.
/// Call `writeMessage` and `readMessage` alternately; the final message returns a
/// `Transport`. A decrypt or DH failure after a message pattern is consumed is
/// terminal: the handshake refuses further use and must be discarded.
public final class HandshakeState: Sendable {
    private let core: Mutex<Core>

    init(
        protocol: NoiseProtocol,
        initiator: Bool,
        prologue: [UInt8],
        localStatic: KeyPair?,
        remoteStatic: [UInt8]?,
        psks: inout [[UInt8]]
    ) throws {
        core = Mutex(try Core(
            protocol: `protocol`, initiator: initiator, prologue: prologue,
            localStatic: localStatic, remoteStatic: remoteStatic, psks: &psks))
    }

    /// The peer's static public key once known: at once when it was passed to
    /// `createHandshake`, after the message that carried it otherwise. Nil after a
    /// terminal failure. Raises `TorannError.closed` after `close()`.
    public var remoteStaticPublicKey: Data? {
        get throws { try core.withLock { try $0.remoteStaticPublicKey() } }
    }

    /// Installs the ephemeral private key the next `e` token uses instead of a random one.
    /// Internal rather than private because the Flutter and React Native hosts compile
    /// these sources into their own modules and call it.
    func setFixedEphemeral(_ privateKey: Data) throws {
        try core.withLock { try $0.setFixedEphemeral(privateKey) }
    }

    /// Writes the next handshake message (Noise §5.3 WriteMessage).
    public func writeMessage(payload: Data = Data()) throws -> HandshakeWriteResult {
        try core.withLock { try $0.writeMessage(payload: payload) }
    }

    /// Reads the next handshake message from the peer (Noise §5.3 ReadMessage).
    public func readMessage(_ message: Data) throws -> HandshakeReadResult {
        try core.withLock { try $0.readMessage(message) }
    }

    /// Zeros all key material. Every operation afterwards raises `TorannError.closed`.
    public func close() {
        core.withLock { $0.close() }
    }

    deinit {
        close()
    }
}

private struct Core {
    private let symmetric: SymmetricState
    private let dh: NoiseDh
    private let initiator: Bool
    private let oneWay: Bool
    private let hasPsk: Bool
    private var messagePatterns: [[Token]]
    private var psks: [[UInt8]]
    private var turnToWrite: Bool
    private var finished = false
    private var failed = false
    private var closed = false

    private var sPrivate: [UInt8]?
    private var sPublic: [UInt8]?
    private var ePrivate: [UInt8]?
    private var ePublic: [UInt8]?
    private var rs: [UInt8]?
    private var re: [UInt8]?

    private var fixedEphemeral: [UInt8]?

    init(
        protocol: NoiseProtocol,
        initiator: Bool,
        prologue: [UInt8],
        localStatic: KeyPair?,
        remoteStatic: [UInt8]?,
        psks: inout [[UInt8]]
    ) throws {
        dh = `protocol`.dh
        self.initiator = initiator
        let pattern = `protocol`.pattern
        oneWay = pattern.messages.count == 1
        turnToWrite = initiator
        hasPsk = `protocol`.pskCount > 0

        // Every check runs before any key is kept. The PSK copies arrive `inout` so that a
        // failed check wipes the caller's uniquely owned arrays in place, and the static
        // private key copy is wiped on the same path.
        var staticPrivate: [UInt8]?
        do {
            for psk in psks where psk.count != 32 {
                throw TorannError.invalidArgument("Pre-shared keys must be 32 bytes.")
            }
            if psks.count != `protocol`.pskCount {
                throw TorannError.invalidArgument(
                    "The protocol requires \(`protocol`.pskCount) pre-shared key(s); \(psks.count) were provided.")
            }

            let needsLocalStatic = initiator ? pattern.initiatorSendsStatic : pattern.responderSendsStatic
            let needsRemoteStatic = initiator ? pattern.hasResponderPreStatic : pattern.hasInitiatorPreStatic
            if needsLocalStatic && localStatic == nil {
                throw TorannError.invalidArgument("A local static key is required by the handshake pattern.")
            }
            if needsRemoteStatic && remoteStatic == nil {
                throw TorannError.invalidArgument("The remote static public key is required by the handshake pattern.")
            }

            // The private key is read before the remote key check because a closed key
            // pair raises `closed` there.
            if let localStatic {
                staticPrivate = try localStatic.copyPrivateKey()
                sPublic = try localStatic.copyPublicKey()
            }
            if let remoteStatic, remoteStatic.count != dh.dhLen {
                throw TorannError.invalidArgument("Remote static public key must be \(dh.dhLen) bytes.")
            }
        } catch {
            wipe(&staticPrivate)
            for i in psks.indices { wipe(&psks[i]) }
            throw error
        }
        sPrivate = staticPrivate
        rs = remoteStatic
        self.psks = psks
        psks.removeAll()

        messagePatterns = pattern.messages
        symmetric = SymmetricState(protocolName: `protocol`.name, cipher: `protocol`.cipher, hash: `protocol`.hash)
        symmetric.mixHash(prologue)

        do {
            for token in pattern.preInitiator {
                try mixPreMessage(token, initiatorSide: true)
            }
            for token in pattern.preResponder {
                try mixPreMessage(token, initiatorSide: false)
            }
        } catch {
            close()
            throw error
        }
    }

    func remoteStaticPublicKey() throws -> Data? {
        if closed { throw TorannError.closed }
        guard !failed, let rs else { return nil }
        return Data(rs)
    }

    mutating func setFixedEphemeral(_ privateKey: Data) throws {
        if closed { throw TorannError.closed }
        guard privateKey.count == dh.dhLen else {
            throw TorannError.invalidArgument("The private key must be \(dh.dhLen) bytes.")
        }
        wipe(&fixedEphemeral)
        fixedEphemeral = Array(privateKey)
    }

    mutating func writeMessage(payload: Data) throws -> HandshakeWriteResult {
        try throwIfUnavailable()
        if !turnToWrite {
            throw TorannError.invalidState("It is not this party's turn to write a message.")
        }

        let tokens = messagePatterns[0]
        let (prefix, hasKey) = simulate(tokens)
        let size = prefix + payload.count + (hasKey ? Transport.tagSize : 0)
        if size > NoiseProtocol.maxMessageLength {
            throw TorannError.invalidArgument("A Noise message must not exceed \(NoiseProtocol.maxMessageLength) bytes.")
        }
        let payloadBytes = Array(payload)

        do {
            messagePatterns.removeFirst()
            var message: [UInt8] = []
            message.reserveCapacity(size)
            for token in tokens {
                switch token {
                case .e:
                    wipe(&ePrivate)
                    if fixedEphemeral != nil {
                        ePrivate = fixedEphemeral
                        fixedEphemeral = nil
                    } else {
                        ePrivate = dh.generatePrivateKey()
                    }
                    let ePub = try dh.derivePublicKey(privateKey: ePrivate!)
                    ePublic = ePub
                    message += ePub
                    symmetric.mixHash(ePub)
                    if hasPsk {
                        try symmetric.mixKey(ePub)
                    }
                case .s:
                    guard let sPublic else {
                        throw TorannError.invalidState("A local static key is required.")
                    }
                    message += try symmetric.encryptAndHash(sPublic)
                case .psk:
                    try mixPsk()
                default:
                    try mixDh(token)
                }
            }

            message += try symmetric.encryptAndHash(payloadBytes)
            turnToWrite = false
            let (hash, transport) = try finish()
            return HandshakeWriteResult(message: Data(message), handshakeHash: hash.map { Data($0) }, transport: transport)
        } catch {
            failed = true
            throw error
        }
    }

    mutating func readMessage(_ message: Data) throws -> HandshakeReadResult {
        try throwIfUnavailable()
        if turnToWrite {
            throw TorannError.invalidState("It is not this party's turn to read a message.")
        }
        if message.count > NoiseProtocol.maxMessageLength {
            throw TorannError.invalidArgument("A Noise message must not exceed \(NoiseProtocol.maxMessageLength) bytes.")
        }
        let bytes = Array(message)

        let tokens = messagePatterns[0]
        let (prefix, hasKey) = simulate(tokens)
        let minLength = prefix + (hasKey ? Transport.tagSize : 0)
        if bytes.count < minLength {
            throw TorannError.authenticationFailed("The handshake message is truncated.")
        }

        do {
            messagePatterns.removeFirst()
            var offset = 0
            for token in tokens {
                switch token {
                case .e:
                    let next = offset + dh.dhLen
                    try require(next <= bytes.count)
                    let rePublic = Array(bytes[offset..<next])
                    offset = next
                    re = rePublic
                    symmetric.mixHash(rePublic)
                    if hasPsk {
                        try symmetric.mixKey(rePublic)
                    }
                case .s:
                    let length = dh.dhLen + (symmetric.cipherHasKey ? Transport.tagSize : 0)
                    let next = offset + length
                    try require(next <= bytes.count)
                    rs = try symmetric.decryptAndHash(Array(bytes[offset..<next]))
                    offset = next
                case .psk:
                    try mixPsk()
                default:
                    try mixDh(token)
                }
            }

            let payload = try symmetric.decryptAndHash(Array(bytes[offset...]))
            turnToWrite = true
            let (hash, transport) = try finish()
            return HandshakeReadResult(payload: Data(payload), handshakeHash: hash.map { Data($0) }, transport: transport)
        } catch {
            failed = true
            throw error
        }
    }

    private mutating func finish() throws -> ([UInt8]?, Transport?) {
        if !messagePatterns.isEmpty {
            return (nil, nil)
        }
        finished = true
        let handshakeHash = symmetric.handshakeHash
        let (c1, c2) = try symmetric.split()
        clearHandshakeSecrets()
        return (handshakeHash, Transport(initiator: initiator, c1: c1, c2: c2, oneWay: oneWay))
    }

    private mutating func clearHandshakeSecrets() {
        symmetric.clearSecrets()
        wipe(&sPrivate)
        wipe(&ePrivate)
        wipe(&fixedEphemeral)
        for i in psks.indices { wipe(&psks[i]) }
        psks.removeAll()
    }

    /// The minimum-length check before the token loop makes these guards redundant today;
    /// they keep a future mismatch between `simulate` and the loop a thrown error rather
    /// than an out-of-range trap.
    private func require(_ condition: Bool) throws {
        if !condition {
            throw TorannError.authenticationFailed("The handshake message is truncated.")
        }
    }

    /// Returns the byte length of the token prefix and whether a cipher key exists
    /// after the tokens, which decides whether the payload carries a tag.
    private func simulate(_ tokens: [Token]) -> (prefix: Int, hasKey: Bool) {
        var size = 0
        var hasKey = symmetric.cipherHasKey
        for token in tokens {
            switch token {
            case .e:
                size += dh.dhLen
                if hasPsk { hasKey = true }
            case .s:
                size += dh.dhLen + (hasKey ? Transport.tagSize : 0)
            case .psk:
                hasKey = true
            default:
                hasKey = true
            }
        }
        return (size, hasKey)
    }

    private func mixPreMessage(_ token: Token, initiatorSide: Bool) throws {
        guard token == .s else {
            throw TorannError.unsupportedFunction("Only 's' pre-message tokens are supported.")
        }
        let key = initiatorSide == initiator ? sPublic : rs
        guard let key else {
            throw TorannError.invalidState("A static key required by the handshake pattern's pre-messages is missing.")
        }
        symmetric.mixHash(key)
    }

    private mutating func mixPsk() throws {
        guard !psks.isEmpty else {
            throw TorannError.invalidState("The handshake pattern requires a pre-shared key that was not provided.")
        }
        var psk = psks.removeFirst()
        try symmetric.mixKeyAndHash(psk)
        wipe(&psk)
    }

    private func mixDh(_ token: Token) throws {
        let pair: ([UInt8]?, [UInt8]?)
        switch token {
        case .ee: pair = (ePrivate, re)
        case .ss: pair = (sPrivate, rs)
        case .es: pair = initiator ? (ePrivate, rs) : (sPrivate, re)
        case .se: pair = initiator ? (sPrivate, re) : (ePrivate, rs)
        default: throw TorannError.invalidState("Unexpected token \(token).")
        }
        guard let privateKey = pair.0, let publicKey = pair.1 else {
            throw TorannError.invalidState("Key material for the '\(token)' token is missing.")
        }
        var shared = try dh.dh(privateKey: privateKey, publicKey: publicKey)
        try symmetric.mixKey(shared)
        wipe(&shared)
    }

    private func throwIfUnavailable() throws {
        if closed { throw TorannError.closed }
        if failed { throw TorannError.invalidState("The handshake has failed and must be discarded.") }
        if finished { throw TorannError.invalidState("The handshake is already complete.") }
    }

    mutating func close() {
        if closed { return }
        closed = true
        failed = true
        symmetric.close()
        wipe(&sPrivate)
        wipe(&ePrivate)
        wipe(&fixedEphemeral)
        for i in psks.indices { wipe(&psks[i]) }
        psks.removeAll()
    }
}
