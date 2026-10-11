// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// The iOS side of the Flutter plugin. It implements the Pigeon host API over the Swift
// implementation, whose sources are copied into Torann/ by lib/sync-flutter-sources.
// It keeps a table of open key pairs, handshakes, and transports, named by integer
// handles, and contains no cryptography of its own.

import Flutter
import Foundation

public class TorannPlugin: NSObject, FlutterPlugin {
    private let host = TorannHost()

    public static func register(with registrar: FlutterPluginRegistrar) {
        let plugin = TorannPlugin()
        TorannHostApiSetup.setUp(binaryMessenger: registrar.messenger(), api: plugin.host)
        // Publishing keeps the instance alive and delivers detachFromEngine.
        registrar.publish(plugin)
    }

    /// Closes every open key pair, handshake, and transport when the engine detaches,
    /// so that key material is wiped rather than left to deinit.
    public func detachFromEngine(for registrar: FlutterPluginRegistrar) {
        host.closeAll()
        TorannHostApiSetup.setUp(binaryMessenger: registrar.messenger(), api: nil)
    }
}

final class TorannHost: TorannHostApi {
    private let lock = NSLock()
    private var nextHandle: Int64 = 1
    private var shutDown = false
    private var keyPairs: [Int64: KeyPair] = [:]
    private var handshakes: [Int64: HandshakeState] = [:]
    private var transports: [Int64: Transport] = [:]

    // MARK: Protocol

    func parseProtocol(name: String) throws {
        try wrap { _ = try NoiseProtocol.parse(name) }
    }

    // MARK: Key pairs

    func generateKeyPair(protocol name: String) throws -> KeyPairMessage {
        try wrap {
            let keys = try NoiseProtocol.parse(name).generateKeyPair()
            return KeyPairMessage(handle: try store(keys), publicKey: bytes(try keys.publicKey))
        }
    }

    func createKeyPair(protocol name: String, privateKey: FlutterStandardTypedData) throws -> KeyPairMessage {
        try wrap {
            let keys = try NoiseProtocol.parse(name).createKeyPair(privateKey: privateKey.data)
            return KeyPairMessage(handle: try store(keys), publicKey: bytes(try keys.publicKey))
        }
    }

    func keyPairPrivateKey(keyPair: Int64) throws -> FlutterStandardTypedData {
        try wrap { bytes(try self.keyPair(keyPair).privateKey) }
    }

    func closeKeyPair(keyPair: Int64) throws {
        lock.lock()
        let keys = keyPairs.removeValue(forKey: keyPair)
        lock.unlock()
        keys?.close()
    }

    // MARK: Handshakes

    func createHandshake(
        protocol name: String, initiator: Bool, prologue: FlutterStandardTypedData,
        localStatic: Int64?, remoteStatic: FlutterStandardTypedData?, psks: [FlutterStandardTypedData]
    ) throws -> Int64 {
        try wrap {
            let local = try localStatic.map { try self.keyPair($0) }
            let handshake = try NoiseProtocol.parse(name).createHandshake(
                initiator: initiator,
                prologue: prologue.data,
                localStatic: local,
                remoteStatic: remoteStatic?.data,
                psks: psks.map { $0.data })
            return try store(handshake)
        }
    }

    func handshakeWrite(handshake: Int64, payload: FlutterStandardTypedData) throws -> HandshakeWriteMessage {
        try wrap {
            let result = try self.handshake(handshake).writeMessage(payload: payload.data)
            return HandshakeWriteMessage(
                message: bytes(result.message),
                handshakeHash: result.handshakeHash.map(bytes),
                transportHandle: try result.transport.map { try store($0) })
        }
    }

    func handshakeRead(handshake: Int64, message: FlutterStandardTypedData) throws -> HandshakeReadMessage {
        try wrap {
            let result = try self.handshake(handshake).readMessage(message.data)
            return HandshakeReadMessage(
                payload: bytes(result.payload),
                handshakeHash: result.handshakeHash.map(bytes),
                transportHandle: try result.transport.map { try store($0) })
        }
    }

    func handshakeRemoteStaticPublicKey(handshake: Int64) throws -> FlutterStandardTypedData? {
        try wrap { try self.handshake(handshake).remoteStaticPublicKey.map(bytes) }
    }

    func closeHandshake(handshake: Int64) throws {
        lock.lock()
        let state = handshakes.removeValue(forKey: handshake)
        lock.unlock()
        state?.close()
    }

    // MARK: Transports

    func transportWrite(transport: Int64, payload: FlutterStandardTypedData) throws -> FlutterStandardTypedData {
        try wrap { bytes(try self.transport(transport).writeMessage(payload: payload.data)) }
    }

    func transportRead(transport: Int64, message: FlutterStandardTypedData) throws -> FlutterStandardTypedData {
        try wrap { bytes(try self.transport(transport).readMessage(message.data)) }
    }

    func transportRekeySend(transport: Int64) throws {
        try wrap { try self.transport(transport).rekeySend() }
    }

    func transportRekeyReceive(transport: Int64) throws {
        try wrap { try self.transport(transport).rekeyReceive() }
    }

    func transportSetSendNonce(transport: Int64, nonce: Int64) throws {
        try wrap { try self.transport(transport).setSendNonce(try nonceValue(nonce)) }
    }

    func transportSetReceiveNonce(transport: Int64, nonce: Int64) throws {
        try wrap { try self.transport(transport).setReceiveNonce(try nonceValue(nonce)) }
    }

    func closeTransport(transport: Int64) throws {
        lock.lock()
        let state = transports.removeValue(forKey: transport)
        lock.unlock()
        state?.close()
    }

    // MARK: Test-only

    func setFixedEphemeral(handshake: Int64, privateKey: FlutterStandardTypedData) throws {
        try wrap { try self.handshake(handshake).setFixedEphemeral(privateKey.data) }
    }

    // MARK: Lifecycle

    /// Host calls run on a serial background queue and this runs on the platform thread,
    /// so a call can finish after the tables are emptied; `shutDown` makes its `store`
    /// close the new object instead of keeping it.
    func closeAll() {
        lock.lock()
        shutDown = true
        let keys = Array(keyPairs.values), states = Array(handshakes.values), channels = Array(transports.values)
        keyPairs.removeAll(); handshakes.removeAll(); transports.removeAll()
        lock.unlock()
        keys.forEach { $0.close() }
        states.forEach { $0.close() }
        channels.forEach { $0.close() }
    }

    // MARK: Handle table

    private func store(_ keys: KeyPair) throws -> Int64 {
        lock.lock(); defer { lock.unlock() }
        if shutDown { keys.close(); throw TorannError.closed }
        let h = nextHandle; nextHandle += 1; keyPairs[h] = keys; return h
    }

    private func store(_ state: HandshakeState) throws -> Int64 {
        lock.lock(); defer { lock.unlock() }
        if shutDown { state.close(); throw TorannError.closed }
        let h = nextHandle; nextHandle += 1; handshakes[h] = state; return h
    }

    private func store(_ state: Transport) throws -> Int64 {
        lock.lock(); defer { lock.unlock() }
        if shutDown { state.close(); throw TorannError.closed }
        let h = nextHandle; nextHandle += 1; transports[h] = state; return h
    }

    private func keyPair(_ handle: Int64) throws -> KeyPair {
        lock.lock(); defer { lock.unlock() }
        guard let keys = keyPairs[handle] else { throw TorannError.closed }
        return keys
    }

    private func handshake(_ handle: Int64) throws -> HandshakeState {
        lock.lock(); defer { lock.unlock() }
        guard let state = handshakes[handle] else { throw TorannError.closed }
        return state
    }

    private func transport(_ handle: Int64) throws -> Transport {
        lock.lock(); defer { lock.unlock() }
        guard let state = transports[handle] else { throw TorannError.closed }
        return state
    }

    // MARK: Conversion

    private func nonceValue(_ nonce: Int64) throws -> UInt64 {
        guard nonce >= 0 else { throw TorannError.invalidArgument("The nonce must not be negative.") }
        return UInt64(nonce)
    }

    private func bytes(_ data: Data) -> FlutterStandardTypedData { FlutterStandardTypedData(bytes: data) }

    /// Runs one host call and converts a `TorannError` into a `PigeonError` whose code is
    /// the shared error category, which the Dart layer maps back to a typed exception. Any
    /// other error becomes `hostFailure` with only its type name, so no uncontrolled text
    /// crosses the boundary.
    private func wrap<T>(_ body: () throws -> T) throws -> T {
        do {
            return try body()
        } catch let error as TorannError {
            throw PigeonError(code: Self.code(error), message: error.message, details: nil)
        } catch let error as PigeonError {
            throw error
        } catch {
            throw PigeonError(code: "hostFailure", message: String(describing: type(of: error)), details: nil)
        }
    }

    private static func code(_ error: TorannError) -> String {
        switch error {
        case .invalidProtocolName: return "invalidProtocolName"
        case .unsupportedFunction: return "unsupportedFunction"
        case .invalidArgument: return "invalidArgument"
        case .invalidState: return "invalidState"
        case .authenticationFailed: return "authenticationFailed"
        case .closed: return "closed"
        }
    }
}
