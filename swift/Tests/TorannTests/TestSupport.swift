// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import Foundation
import XCTest
@testable import Torann

func hex(_ s: String) -> Data {
    var data = Data(capacity: s.count / 2)
    var index = s.startIndex
    while index < s.endIndex {
        let next = s.index(index, offsetBy: 2)
        data.append(UInt8(s[index..<next], radix: 16)!)
        index = next
    }
    return data
}

func hexString(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func randomBytes(_ count: Int) -> Data {
    Data((0..<count).map { _ in UInt8.random(in: 0...255) })
}

/// The repository's shared `vectors/` folder, located from this source file's path.
/// The iOS Simulator runs tests as a macOS process, so the host path is readable
/// there as well as under `swift test`.
let vectorsDirectory: URL = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()  // TorannTests
    .deletingLastPathComponent()  // Tests
    .deletingLastPathComponent()  // swift
    .deletingLastPathComponent()  // repo root
    .appendingPathComponent("vectors")

/// Completes an NN handshake and returns (initiator transport, responder transport).
func completeNn() throws -> (Transport, Transport) {
    let proto = try NoiseProtocol.parse("Noise_NN_25519_ChaChaPoly_SHA256")
    let initiator = try proto.createHandshake(initiator: true)
    let responder = try proto.createHandshake(initiator: false)
    defer { initiator.close(); responder.close() }
    let m1 = try initiator.writeMessage()
    _ = try responder.readMessage(m1.message)
    let m2 = try responder.writeMessage()
    let r2 = try initiator.readMessage(m2.message)
    return (r2.transport!, m2.transport!)
}

func assertThrows<T>(_ expression: @autoclosure () throws -> T, _ check: (TorannError) -> Bool, file: StaticString = #filePath, line: UInt = #line) {
    do {
        _ = try expression()
        XCTFail("expected a TorannError", file: file, line: line)
    } catch let error as TorannError {
        XCTAssertTrue(check(error), "unexpected error \(error)", file: file, line: line)
    } catch {
        XCTFail("expected a TorannError, got \(error)", file: file, line: line)
    }
}
