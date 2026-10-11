// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// The Swift interop driver. It reads one command per line from stdin and writes one
// response line per command, following the protocol in interop/README.md.

import Foundation
import Torann

func hex(_ data: Data?) -> String {
    guard let data, !data.isEmpty else { return "-" }
    return data.map { String(format: "%02x", $0) }.joined()
}

func unhex(_ s: String) -> Data {
    if s == "-" { return Data() }
    var data = Data(capacity: s.count / 2)
    var index = s.startIndex
    while index < s.endIndex {
        let next = s.index(index, offsetBy: 2)
        data.append(UInt8(s[index..<next], radix: 16)!)
        index = next
    }
    return data
}

func category(_ error: Error) -> String {
    guard let e = error as? TorannError else { return "invalidState" }
    switch e {
    case .invalidProtocolName: return "invalidProtocolName"
    case .unsupportedFunction: return "unsupportedFunction"
    case .invalidArgument: return "invalidArgument"
    case .invalidState: return "invalidState"
    case .authenticationFailed: return "authenticationFailed"
    case .closed: return "closed"
    }
}

final class Session {
    var handshake: HandshakeState?
    var transport: Transport?
    var handshakeHash: Data?

    func execute(_ parts: [String]) throws -> String {
        switch parts[0] {
        case "keygen":
            let proto = try NoiseProtocol.parse(parts[1])
            let keys = try proto.generateKeyPair()
            defer { keys.close() }
            return "ok \(hex(try keys.privateKey)) \(hex(try keys.publicKey))"
        case "init":
            reset()
            let proto = try NoiseProtocol.parse(parts[1])
            let local = parts[4] == "-" ? nil : try proto.createKeyPair(privateKey: unhex(parts[4]))
            defer { local?.close() }
            let psks = parts[6] == "-" ? [] : parts[6].split(separator: ",").map { unhex(String($0)) }
            handshake = try proto.createHandshake(
                initiator: parts[2] == "initiator",
                prologue: unhex(parts[3]),
                localStatic: local,
                remoteStatic: parts[5] == "-" ? nil : unhex(parts[5]),
                psks: psks)
            return "ok"
        case "write":
            let payload = unhex(parts[1])
            if let transport {
                return "ok \(hex(try transport.writeMessage(payload: payload)))"
            }
            let result = try requireHandshake().writeMessage(payload: payload)
            return complete(result.handshakeHash, result.transport) ? "ok \(hex(result.message)) done \(hex(handshakeHash))" : "ok \(hex(result.message))"
        case "read":
            let message = unhex(parts[1])
            if let transport {
                return "ok \(hex(try transport.readMessage(message)))"
            }
            let result = try requireHandshake().readMessage(message)
            return complete(result.handshakeHash, result.transport) ? "ok \(hex(result.payload)) done \(hex(handshakeHash))" : "ok \(hex(result.payload))"
        case "rekey":
            let t = try requireTransport()
            if parts[1] == "send" { try t.rekeySend() } else { try t.rekeyReceive() }
            return "ok"
        case "hash":
            guard let handshakeHash else { throw TorannError.invalidState("The handshake is not complete.") }
            return "ok \(hex(handshakeHash))"
        case "remote-static":
            return "ok \(hex(try requireHandshake().remoteStaticPublicKey))"
        default:
            throw TorannError.invalidArgument("Unknown command '\(parts[0])'.")
        }
    }

    private func requireHandshake() throws -> HandshakeState {
        guard let handshake else { throw TorannError.invalidState("No session; send init first.") }
        return handshake
    }

    private func requireTransport() throws -> Transport {
        guard let transport else { throw TorannError.invalidState("The handshake is not complete.") }
        return transport
    }

    private func complete(_ hash: Data?, _ transport: Transport?) -> Bool {
        guard let transport else { return false }
        self.transport = transport
        handshakeHash = hash
        return true
    }

    private func reset() {
        handshake?.close()
        transport?.close()
        handshake = nil
        transport = nil
        handshakeHash = nil
    }
}

let session = Session()
setvbuf(stdout, nil, _IOLBF, 0)
while let line = readLine() {
    let parts = line.split(separator: " ").map(String.init)
    if parts.isEmpty { continue }
    if parts[0] == "quit" {
        print("ok")
        break
    }
    do {
        print(try session.execute(parts))
    } catch {
        let message = (error as? TorannError)?.message ?? "\(error)"
        print("error \(category(error)) \(message.replacingOccurrences(of: "\n", with: " "))")
    }
}
