// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import Foundation
import XCTest
@testable import Torann

final class SecurityTests: XCTestCase {
    func testTransportWriteAfterCloseThrows() throws {
        let (initiator, responder) = try completeNn()
        initiator.close()
        assertThrows(try initiator.writeMessage(payload: Data("secret!!".utf8))) { $0 == .closed }
        responder.close()
    }

    func testTransportReadAfterCloseThrows() throws {
        let (initiator, responder) = try completeNn()
        let message = try initiator.writeMessage(payload: Data("hello".utf8))
        responder.close()
        assertThrows(try responder.readMessage(message)) { $0 == .closed }
        initiator.close()
    }

    func testMidHandshakeCloseThenWriteThrows() throws {
        let proto = try NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_SHA256")
        let initStatic = try proto.generateKeyPair()
        let respStatic = try proto.generateKeyPair()
        let initiator = try proto.createHandshake(initiator: true, localStatic: initStatic)
        let responder = try proto.createHandshake(initiator: false, localStatic: respStatic)

        let m1 = try initiator.writeMessage()
        _ = try responder.readMessage(m1.message)
        let m2 = try responder.writeMessage()
        _ = try initiator.readMessage(m2.message)

        initiator.close()
        assertThrows(try initiator.writeMessage()) { $0 == .closed }
        assertThrows(try initiator.remoteStaticPublicKey) { $0 == .closed }
        responder.close()
    }

    func testTamperedHandshakeReadIsTerminal() throws {
        let proto = try NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_SHA256")
        let initStatic = try proto.generateKeyPair()
        let respStatic = try proto.generateKeyPair()
        let initiator = try proto.createHandshake(initiator: true, localStatic: initStatic)
        let responder = try proto.createHandshake(initiator: false, localStatic: respStatic)
        defer { initiator.close(); responder.close() }

        let m1 = try initiator.writeMessage()
        _ = try responder.readMessage(m1.message)
        let good = try responder.writeMessage().message
        var tampered = good
        tampered[tampered.count - 1] ^= 0xFF

        assertThrows(try initiator.readMessage(tampered)) {
            if case .authenticationFailed = $0 { return true } else { return false }
        }
        assertThrows(try initiator.readMessage(good)) {
            if case .invalidState(let m) = $0 { return m.lowercased().contains("failed") } else { return false }
        }
        XCTAssertNil(try initiator.remoteStaticPublicKey)
    }

    func testTruncatedHandshakeMessageIsRejectedAndNotTerminal() throws {
        // The length check runs before the message pattern is consumed, so the handshake
        // stays usable.
        let proto = try NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        let initiator = try proto.createHandshake(initiator: true)
        let responder = try proto.createHandshake(initiator: false)
        defer { initiator.close(); responder.close() }

        let m1 = try initiator.writeMessage().message
        assertThrows(try responder.readMessage(m1.prefix(10))) { $0 == .authenticationFailed("The handshake message is truncated.") }
        _ = try responder.readMessage(m1)
        let m2 = try responder.writeMessage()
        XCTAssertNotNil(m2.transport)
    }

    func testOversizedHandshakePayloadDoesNotConsumeTheMessagePattern() throws {
        let proto = try NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        let initiator = try proto.createHandshake(initiator: true)
        let responder = try proto.createHandshake(initiator: false)
        defer { initiator.close(); responder.close() }

        assertThrows(try initiator.writeMessage(payload: Data(repeating: 1, count: 70_000))) {
            $0 == .invalidArgument("A Noise message must not exceed 65535 bytes.")
        }
        let written = try initiator.writeMessage(payload: Data("hi".utf8))
        let read = try responder.readMessage(written.message)
        XCTAssertEqual(read.payload, Data("hi".utf8))
    }

    func testCreateHandshakeRejectsMissingStaticAndPsk() throws {
        let xx = try NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_SHA256")
        assertThrows(try xx.createHandshake(initiator: true)) {
            $0 == .invalidArgument("A local static key is required by the handshake pattern.")
        }

        let xxpsk3 = try NoiseProtocol.parse("Noise_XXpsk3_25519_ChaChaPoly_SHA256")
        let s = try xxpsk3.generateKeyPair()
        assertThrows(try xxpsk3.createHandshake(initiator: true, localStatic: s)) {
            $0 == .invalidArgument("The protocol requires 1 pre-shared key(s); 0 were provided.")
        }
        assertThrows(try xxpsk3.createHandshake(initiator: true, localStatic: s, psks: [Data(repeating: 0, count: 31)])) {
            $0 == .invalidArgument("Pre-shared keys must be 32 bytes.")
        }

        let nk = try NoiseProtocol.parse("Noise_NK_25519_ChaChaPoly_SHA256")
        let nkStatic = try nk.generateKeyPair()
        assertThrows(try nk.createHandshake(initiator: true, localStatic: nkStatic)) {
            $0 == .invalidArgument("The remote static public key is required by the handshake pattern.")
        }
        assertThrows(try nk.createHandshake(initiator: true, remoteStatic: Data(repeating: 0, count: 31))) {
            $0 == .invalidArgument("Remote static public key must be 32 bytes.")
        }

        nkStatic.close()
        assertThrows(try xx.createHandshake(initiator: true, localStatic: nkStatic)) { $0 == .closed }
    }

    func testKeyPairReturnsCopiesAndThrowsAfterClose() throws {
        let proto = try NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        let keys = try proto.generateKeyPair()
        var copy = try keys.privateKey
        let original = copy[0]
        copy[0] ^= 0xFF
        XCTAssertEqual(try keys.privateKey[0], original)
        XCTAssertEqual(try keys.publicKey.count, 32)

        let rebuilt = try proto.createKeyPair(privateKey: try keys.privateKey)
        XCTAssertEqual(try rebuilt.publicKey, try keys.publicKey)
        assertThrows(try proto.createKeyPair(privateKey: Data(repeating: 1, count: 31))) {
            $0 == .invalidArgument("The private key must be 32 bytes.")
        }

        keys.close()
        assertThrows(try keys.privateKey) { $0 == .closed }
        assertThrows(try keys.publicKey) { $0 == .closed }
        keys.close()
    }

    func testRekeyRotatesTransportKeysWithoutResettingNonces() throws {
        let (initiator, responder) = try completeNn()
        defer { initiator.close(); responder.close() }

        let first = try initiator.writeMessage(payload: Data("one".utf8))
        XCTAssertEqual(try responder.readMessage(first), Data("one".utf8))

        try initiator.rekeySend()
        let second = try initiator.writeMessage(payload: Data("two".utf8))
        assertThrows(try responder.readMessage(second)) {
            if case .authenticationFailed = $0 { return true } else { return false }
        }

        try responder.rekeyReceive()
        XCTAssertEqual(try responder.readMessage(second), Data("two".utf8))
    }

    func testSetReceiveNonceAllowsReplayOfAPreviousCiphertext() throws {
        let (initiator, responder) = try completeNn()
        defer { initiator.close(); responder.close() }
        let saved = try initiator.writeMessage(payload: Data("ping".utf8))
        _ = try responder.readMessage(saved)
        try responder.setReceiveNonce(0)
        XCTAssertEqual(try responder.readMessage(saved), Data("ping".utf8))
        assertThrows(try responder.setReceiveNonce(UInt64.max)) { $0 == .invalidArgument("Nonce 2^64-1 is reserved.") }
    }

    func testNonceExhaustionIsAnInvalidStateError() throws {
        let (initiator, responder) = try completeNn()
        defer { initiator.close(); responder.close() }
        try initiator.setSendNonce(UInt64.max - 1)
        _ = try initiator.writeMessage(payload: Data("last".utf8))
        assertThrows(try initiator.writeMessage(payload: Data("none".utf8))) {
            $0 == .invalidState("Nonce exhausted; the session must be re-established.")
        }
    }

    func testRemoteStaticPublicKeyIsAvailableAfterSuccessfulXxMessage2() throws {
        let proto = try NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_SHA256")
        let initStatic = try proto.generateKeyPair()
        let respStatic = try proto.generateKeyPair()
        let initiator = try proto.createHandshake(initiator: true, localStatic: initStatic)
        let responder = try proto.createHandshake(initiator: false, localStatic: respStatic)
        defer { initiator.close(); responder.close() }

        let m1 = try initiator.writeMessage()
        _ = try responder.readMessage(m1.message)
        XCTAssertNil(try initiator.remoteStaticPublicKey)

        let m2 = try responder.writeMessage()
        _ = try initiator.readMessage(m2.message)
        XCTAssertEqual(try initiator.remoteStaticPublicKey, try respStatic.publicKey)

        let nk = try NoiseProtocol.parse("Noise_NK_25519_ChaChaPoly_SHA256")
        let nkInit = try nk.createHandshake(initiator: true, remoteStatic: try respStatic.publicKey)
        XCTAssertEqual(try nkInit.remoteStaticPublicKey, try respStatic.publicKey)
        nkInit.close()
    }

    func testOneWayTransportRejectsTheReverseDirection() throws {
        let proto = try NoiseProtocol.parse("Noise_N_25519_AESGCM_SHA256")
        let respStatic = try proto.generateKeyPair()
        let initiator = try proto.createHandshake(initiator: true, remoteStatic: try respStatic.publicKey)
        let responder = try proto.createHandshake(initiator: false, localStatic: respStatic)
        defer { initiator.close(); responder.close() }

        let written = try initiator.writeMessage()
        let read = try responder.readMessage(written.message)
        let initTransport = try XCTUnwrap(written.transport)
        let respTransport = try XCTUnwrap(read.transport)
        defer { initTransport.close(); respTransport.close() }

        let message = try initTransport.writeMessage(payload: Data("one way".utf8))
        XCTAssertEqual(try respTransport.readMessage(message), Data("one way".utf8))

        let responderSends = "A one-way pattern's responder cannot send transport messages."
        let initiatorReceives = "A one-way pattern's initiator cannot receive transport messages."
        assertThrows(try respTransport.writeMessage(payload: Data("nope".utf8))) { $0 == .invalidState(responderSends) }
        assertThrows(try respTransport.rekeySend()) { $0 == .invalidState(responderSends) }
        assertThrows(try respTransport.setSendNonce(1)) { $0 == .invalidState(responderSends) }
        assertThrows(try initTransport.readMessage(message)) { $0 == .invalidState(initiatorReceives) }
        assertThrows(try initTransport.rekeyReceive()) { $0 == .invalidState(initiatorReceives) }
        assertThrows(try initTransport.setReceiveNonce(1)) { $0 == .invalidState(initiatorReceives) }
    }

    func testHandshakeTurnAndCompletionErrors() throws {
        let proto = try NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        let initiator = try proto.createHandshake(initiator: true)
        let responder = try proto.createHandshake(initiator: false)
        defer { initiator.close(); responder.close() }

        assertThrows(try responder.writeMessage()) { $0 == .invalidState("It is not this party's turn to write a message.") }
        assertThrows(try initiator.readMessage(Data(repeating: 0, count: 32))) { $0 == .invalidState("It is not this party's turn to read a message.") }

        let m1 = try initiator.writeMessage()
        _ = try responder.readMessage(m1.message)
        let m2 = try responder.writeMessage()
        _ = try initiator.readMessage(m2.message)
        assertThrows(try initiator.writeMessage()) { $0 == .invalidState("The handshake is already complete.") }
        assertThrows(try responder.readMessage(m2.message)) { $0 == .invalidState("The handshake is already complete.") }
        m2.transport?.close()
    }

    func testLowOrderPeerKeyIsATerminalHandshakeFailure() throws {
        // NN message 1 carries only `e`; the first DH (`ee`) happens when the responder
        // writes message 2, so the responder's write fails and becomes terminal.
        let proto = try NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        let initiator = try proto.createHandshake(initiator: true)
        let responder = try proto.createHandshake(initiator: false)
        defer { initiator.close(); responder.close() }

        var m1 = try initiator.writeMessage().message
        m1.replaceSubrange(0..<32, with: Data(repeating: 0, count: 32))
        _ = try responder.readMessage(m1)
        assertThrows(try responder.writeMessage()) { $0 == .authenticationFailed("The peer's public key is invalid.") }
        assertThrows(try responder.writeMessage()) {
            if case .invalidState(let m) = $0 { return m.contains("failed") } else { return false }
        }
    }

    func testEveryOperationThrowsClosedAfterCloseAndCloseIsIdempotent() throws {
        let (initiator, responder) = try completeNn()
        initiator.close()
        initiator.close()
        assertThrows(try initiator.rekeySend()) { $0 == .closed }
        assertThrows(try initiator.rekeyReceive()) { $0 == .closed }
        assertThrows(try initiator.setSendNonce(1)) { $0 == .closed }
        assertThrows(try initiator.setReceiveNonce(1)) { $0 == .closed }
        assertThrows(try initiator.readMessage(Data(repeating: 0, count: 32))) { $0 == .closed }
        responder.close()

        let proto = try NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        let handshake = try proto.createHandshake(initiator: false)
        handshake.close()
        handshake.close()
        assertThrows(try handshake.readMessage(Data(repeating: 0, count: 32))) { $0 == .closed }
        assertThrows(try handshake.setFixedEphemeral(Data(repeating: 1, count: 32))) { $0 == .closed }
    }

    func testFixedEphemeralIsValidatedAndUsedOnce() throws {
        let proto = try NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        let initiator = try proto.createHandshake(initiator: true)
        defer { initiator.close() }
        assertThrows(try initiator.setFixedEphemeral(Data(repeating: 1, count: 31))) { $0 == .invalidArgument("The private key must be 32 bytes.") }
        try initiator.setFixedEphemeral(hex("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"))
        let message = try initiator.writeMessage().message
        XCTAssertEqual(hexString(message.prefix(32)), "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944")
    }

    func testKeyDerivationAndSharedSecretMatchRfc7748() throws {
        // The keys and the shared secret are the RFC 7748 §6.1 example.
        let proto = try NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
        let alice = try proto.createKeyPair(privateKey: hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        let bob = try proto.createKeyPair(privateKey: hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
        defer { alice.close(); bob.close() }
        XCTAssertEqual(hexString(try alice.publicKey), "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        XCTAssertEqual(hexString(try bob.publicKey), "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

        let dh = Curve25519Dh()
        let shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        XCTAssertEqual(hexString(Data(try dh.dh(privateKey: try alice.copyPrivateKey(), publicKey: try bob.copyPublicKey()))), shared)
        XCTAssertEqual(hexString(Data(try dh.dh(privateKey: try bob.copyPrivateKey(), publicKey: try alice.copyPublicKey()))), shared)
    }

    // MARK: Parsing

    func testUnsupportedFunctionsAreRejectedByName() throws {
        assertThrows(try NoiseProtocol.parse("Noise_XX_448_ChaChaPoly_SHA256")) { $0 == .unsupportedFunction("DH function '448' is not supported.") }
        assertThrows(try NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_BLAKE2s")) { $0 == .unsupportedFunction("Hash function 'BLAKE2s' is not supported.") }
        assertThrows(try NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_BLAKE2b")) { $0 == .unsupportedFunction("Hash function 'BLAKE2b' is not supported.") }
        assertThrows(try NoiseProtocol.parse("Noise_XX_448_ChaChaPoly_BLAKE2b")) { $0 == .unsupportedFunction("DH function '448' is not supported.") }
        assertThrows(try NoiseProtocol.parse("Noise_XX_25519_AESCBC_SHA256")) { $0 == .unsupportedFunction("Cipher function 'AESCBC' is not supported.") }
        assertThrows(try NoiseProtocol.parse("Noise_ZZ_25519_ChaChaPoly_SHA256")) { $0 == .unsupportedFunction("Handshake pattern 'ZZ' is not supported.") }
        assertThrows(try NoiseProtocol.parse("Noise_XXfallback_25519_ChaChaPoly_SHA256")) { $0 == .unsupportedFunction("Pattern modifier 'fallback' is not supported.") }
        assertThrows(try NoiseProtocol.parse("Noise_XXpsk+1_25519_ChaChaPoly_SHA256")) { $0 == .unsupportedFunction("Pattern modifier 'psk' is not supported.") }
        assertThrows(try NoiseProtocol.parse("Noise_XXpsk4_25519_ChaChaPoly_SHA256")) { $0 == .unsupportedFunction("psk4 is out of range for pattern XX.") }
        assertThrows(try NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly")) { $0 == .invalidProtocolName("'Noise_XX_25519_ChaChaPoly' is not a valid Noise protocol name.") }
        assertThrows(try NoiseProtocol.parse("")) { $0 == .invalidProtocolName("'' is not a valid Noise protocol name.") }
        XCTAssertEqual(try NoiseProtocol.parse("Noise_NXpsk0+psk1+psk2_25519_AESGCM_SHA512").pskCount, 3)
        XCTAssertEqual(try NoiseProtocol.parse("Noise_X1X1_25519_ChaChaPoly_SHA256").name, "Noise_X1X1_25519_ChaChaPoly_SHA256")
    }

    // MARK: Rekey definition and round trips

    func testRekeyMatchesTheSpecDefinition() throws {
        // No reference suite carries rekey vectors, so this encodes the definition
        // directly: REKEY(k) = ENCRYPT(k, 2^64-1, empty, zeros[32])[..32], nonce preserved.
        let ciphers: [NoiseCipher] = [AesGcmCipher(), ChaChaPolyCipher()]
        for cipher in ciphers {
            let key = Array(randomBytes(32))
            let direct = cipher.createKey(key)
            let rekeyed = try direct.encrypt(nonce: UInt64.max, ad: [], plaintext: [UInt8](repeating: 0, count: 32))
            let expectedKey = cipher.createKey(Array(rekeyed[..<32]))
            let expected = try expectedKey.encrypt(nonce: 5, ad: [], plaintext: Array("handshake!".utf8))

            let state = CipherState(cipher)
            var installed = key
            try state.initializeKey(&installed)
            XCTAssertTrue(installed.allSatisfy { $0 == 0 }, "initializeKey wipes the temporary it is given")
            try state.setNonce(5)
            try state.rekey()
            let actual = try state.encryptWithAd([], Array("handshake!".utf8))
            XCTAssertEqual(actual, expected, cipher.name)
        }
    }

    func testRoundTripWithRandomKeysAcrossSupportedProtocols() throws {
        let names = [
            "Noise_NN_25519_ChaChaPoly_SHA256",
            "Noise_XX_25519_ChaChaPoly_SHA256",
            "Noise_IK_25519_AESGCM_SHA512",
            "Noise_KK_25519_ChaChaPoly_SHA512",
            "Noise_NK_25519_AESGCM_SHA256",
            "Noise_XXpsk3_25519_ChaChaPoly_SHA256",
        ]
        for name in names {
            let proto = try NoiseProtocol.parse(name)
            let initStatic = try proto.generateKeyPair()
            let respStatic = try proto.generateKeyPair()
            let psks = proto.pskCount > 0 ? [randomBytes(32)] : []
            let needsRemote = name.contains("_NK") || name.contains("_KK") || name.contains("_IK")

            let initiator = try proto.createHandshake(
                initiator: true, prologue: Data("torann".utf8), localStatic: initStatic,
                remoteStatic: needsRemote ? try respStatic.publicKey : nil, psks: psks)
            let responder = try proto.createHandshake(
                initiator: false, prologue: Data("torann".utf8), localStatic: respStatic,
                remoteStatic: name.contains("_KK") ? try initStatic.publicKey : nil, psks: psks)

            var writer = initiator, reader = responder
            var initTransport: Transport?, respTransport: Transport?
            while initTransport == nil {
                let written = try writer.writeMessage(payload: Data("ping".utf8))
                let read = try reader.readMessage(written.message)
                XCTAssertEqual(read.payload, Data("ping".utf8), name)
                if let wt = written.transport {
                    initTransport = writer === initiator ? wt : read.transport
                    respTransport = writer === initiator ? read.transport : wt
                }
                swap(&writer, &reader)
            }

            let data = randomBytes(1024)
            XCTAssertEqual(try respTransport!.readMessage(try initTransport!.writeMessage(payload: data)), data, name)
            XCTAssertEqual(try initTransport!.readMessage(try respTransport!.writeMessage(payload: data)), data, name)
            initTransport!.close(); respTransport!.close(); initiator.close(); responder.close()
            initStatic.close(); respStatic.close()
        }
    }

    func testTamperedTransportMessageThrows() throws {
        let (initiator, responder) = try completeNn()
        defer { initiator.close(); responder.close() }
        var message = try initiator.writeMessage(payload: Data("secret".utf8))
        message[2] ^= 0xFF
        assertThrows(try responder.readMessage(message)) {
            if case .authenticationFailed = $0 { return true } else { return false }
        }
        // A failed decrypt leaves the transport usable and its nonce unchanged.
        message[2] ^= 0xFF
        XCTAssertEqual(try responder.readMessage(message), Data("secret".utf8))
        assertThrows(try responder.readMessage(Data(repeating: 0, count: 15))) {
            $0 == .authenticationFailed("Ciphertext is shorter than the authentication tag.")
        }
        assertThrows(try initiator.writeMessage(payload: Data(repeating: 0, count: 65520))) {
            $0 == .invalidArgument("The payload must not exceed 65519 bytes.")
        }
        assertThrows(try responder.readMessage(Data(repeating: 0, count: 65536))) {
            $0 == .invalidArgument("A Noise message must not exceed 65535 bytes.")
        }
    }
}
