// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import Foundation
import XCTest
@testable import Torann

/// Runs the shared vectors with their fixed keys. A vector whose name parses as
/// `unsupportedFunction` is skipped, and the run and skipped counts are asserted exactly
/// so that a parser that starts accepting or rejecting the wrong names fails the test.
final class VectorTests: XCTestCase {
    struct VectorFile: Decodable { let vectors: [Vector] }

    struct Vector: Decodable {
        let protocol_name: String
        let init_prologue: String
        let resp_prologue: String
        let init_static: String?
        let resp_static: String?
        let init_remote_static: String?
        let resp_remote_static: String?
        let init_ephemeral: String?
        let resp_ephemeral: String?
        let init_psks: [String]?
        let resp_psks: [String]?
        let handshake_hash: String?
        let messages: [Message]

        struct Message: Decodable {
            let payload: String
            let ciphertext: String
        }
    }

    func testCacophonyVectors() throws {
        try runFile("cacophony.txt", expectedRun: 236, expectedSkipped: 708)
    }

    func testSnowVectors() throws {
        try runFile("snow.txt", expectedRun: 204, expectedSkipped: 204)
    }

    private func runFile(_ fileName: String, expectedRun: Int, expectedSkipped: Int) throws {
        let url = vectorsDirectory.appendingPathComponent(fileName)
        let file = try JSONDecoder().decode(VectorFile.self, from: Data(contentsOf: url))
        var run = 0
        var skipped = 0

        for vector in file.vectors {
            let proto: NoiseProtocol
            do {
                proto = try NoiseProtocol.parse(vector.protocol_name)
            } catch TorannError.unsupportedFunction {
                skipped += 1
                continue
            }

            do {
                try runVector(proto, vector)
            } catch {
                XCTFail("Vector '\(vector.protocol_name)' failed: \(error)")
                return
            }
            run += 1
        }

        print("\(fileName): ran \(run) vectors, skipped \(skipped) unsupported.")
        XCTAssertEqual(run, expectedRun, "\(fileName): run count")
        XCTAssertEqual(skipped, expectedSkipped, "\(fileName): skipped count")
    }

    private func runVector(_ proto: NoiseProtocol, _ vector: Vector) throws {
        let initStatic = try vector.init_static.map { try proto.createKeyPair(privateKey: hex($0)) }
        let respStatic = try vector.resp_static.map { try proto.createKeyPair(privateKey: hex($0)) }
        defer { initStatic?.close(); respStatic?.close() }

        let initiator = try proto.createHandshake(
            initiator: true,
            prologue: hex(vector.init_prologue),
            localStatic: initStatic,
            remoteStatic: vector.init_remote_static.map(hex),
            psks: (vector.init_psks ?? []).map(hex))
        if let ephemeral = vector.init_ephemeral { try initiator.setFixedEphemeral(hex(ephemeral)) }

        let responder = try proto.createHandshake(
            initiator: false,
            prologue: hex(vector.resp_prologue),
            localStatic: respStatic,
            remoteStatic: vector.resp_remote_static.map(hex),
            psks: (vector.resp_psks ?? []).map(hex))
        if let ephemeral = vector.resp_ephemeral { try responder.setFixedEphemeral(hex(ephemeral)) }
        defer { initiator.close(); responder.close() }

        var initTransport: Transport?
        var respTransport: Transport?
        var oneWay = false
        defer { initTransport?.close(); respTransport?.close() }

        for (i, message) in vector.messages.enumerated() {
            let payload = hex(message.payload)
            let expected = hex(message.ciphertext)
            let initiatorSends = oneWay || i % 2 == 0

            if let it = initTransport, let rt = respTransport {
                let writer = initiatorSends ? it : rt
                let reader = initiatorSends ? rt : it
                let written = try writer.writeMessage(payload: payload)
                XCTAssertEqual(hexString(written), hexString(expected), "\(vector.protocol_name) transport message \(i)")
                let read = try reader.readMessage(expected)
                XCTAssertEqual(hexString(read), hexString(payload), "\(vector.protocol_name) transport payload \(i)")
                continue
            }

            let writer = initiatorSends ? initiator : responder
            let reader = initiatorSends ? responder : initiator
            let written = try writer.writeMessage(payload: payload)
            XCTAssertEqual(hexString(written.message), hexString(expected), "\(vector.protocol_name) message \(i)")
            let read = try reader.readMessage(expected)
            XCTAssertEqual(hexString(read.payload), hexString(payload), "\(vector.protocol_name) payload \(i)")

            if let writerTransport = written.transport {
                guard let readerTransport = read.transport else {
                    XCTFail("\(vector.protocol_name): reader produced no transport"); return
                }
                initTransport = initiatorSends ? writerTransport : readerTransport
                respTransport = initiatorSends ? readerTransport : writerTransport
                if i == 0 { oneWay = true }

                let writerHash = written.handshakeHash.map(hexString)
                let readerHash = read.handshakeHash.map(hexString)
                XCTAssertNotNil(writerHash); XCTAssertNotNil(readerHash)
                XCTAssertEqual(writerHash, readerHash, "\(vector.protocol_name) handshake hashes differ")
                if let expectedHash = vector.handshake_hash {
                    XCTAssertEqual(writerHash, expectedHash, "\(vector.protocol_name) handshake hash")
                }
            } else {
                XCTAssertNil(read.transport)
                XCTAssertNil(written.handshakeHash)
            }
        }
    }
}
