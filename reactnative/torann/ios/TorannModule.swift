// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// The iOS side of the React Native package: the Swift implementation exposed to
// JavaScript through Expo's module API as three shared-object classes. The sources
// under Torann/ are copies written by lib/sync-reactnative-sources; edit
// swift/Sources/Torann instead. sharedObjectDidRelease closes a native object that
// JavaScript released without calling close().

import ExpoModulesCore
import Foundation

final class KeyPairObject: SharedObject {
  let keys: KeyPair

  init(_ keys: KeyPair) {
    self.keys = keys
    super.init()
  }

  override func sharedObjectDidRelease() {
    keys.close()
    super.sharedObjectDidRelease()
  }
}

final class HandshakeObject: SharedObject {
  let handshake: HandshakeState
  var handshakeHash: Data?
  var transport: Transport?

  init(_ handshake: HandshakeState) {
    self.handshake = handshake
    super.init()
  }

  override func sharedObjectDidRelease() {
    handshake.close()
    // A transport that JavaScript never took is closed with the handshake.
    transport?.close()
    super.sharedObjectDidRelease()
  }
}

final class TransportObject: SharedObject {
  let transport: Transport

  init(_ transport: Transport) {
    self.transport = transport
    super.init()
  }

  override func sharedObjectDidRelease() {
    transport.close()
    super.sharedObjectDidRelease()
  }
}

/// Expo wraps a thrown exception in a `FunctionCallException` whose JavaScript message
/// is the wrapper's text, a line break, `→ Caused by: `, and this exception's
/// `debugDescription`, so `debugDescription` is the bare reason, without the exception
/// name and the Swift source location the base class adds.
final class TorannException: Exception, @unchecked Sendable {
  private let errorCode: String
  private let errorReason: String

  init(code: String, reason: String) {
    errorCode = code
    errorReason = reason
    super.init()
  }

  override var code: String { errorCode }
  override var reason: String { errorReason }
  override var debugDescription: String { errorReason }
}

public class TorannModule: Module {
  public func definition() -> ModuleDefinition {
    Name("Torann")

    Function("parseProtocol") { (name: String) in
      try wrap { _ = try NoiseProtocol.parse(name) }
    }

    Function("generateKeyPair") { (name: String) -> KeyPairObject in
      try wrap { KeyPairObject(try NoiseProtocol.parse(name).generateKeyPair()) }
    }

    Function("createKeyPair") { (name: String, privateKey: Data) -> KeyPairObject in
      try wrap { KeyPairObject(try NoiseProtocol.parse(name).createKeyPair(privateKey: privateKey)) }
    }

    Function("createHandshake") { (name: String, initiator: Bool, prologue: Data, localStatic: KeyPairObject?, remoteStatic: Data?, psks: [Data]) -> HandshakeObject in
      try wrap {
        let handshake = try NoiseProtocol.parse(name).createHandshake(
          initiator: initiator, prologue: prologue, localStatic: localStatic?.keys, remoteStatic: remoteStatic, psks: psks)
        return HandshakeObject(handshake)
      }
    }

    Class(KeyPairObject.self) {
      Function("publicKey") { (ref: KeyPairObject) -> Data in try wrap { try ref.keys.publicKey } }
      Function("privateKey") { (ref: KeyPairObject) -> Data in try wrap { try ref.keys.privateKey } }
      Function("close") { (ref: KeyPairObject) in ref.keys.close() }
    }

    Class(HandshakeObject.self) {
      Function("writeMessage") { (ref: HandshakeObject, payload: Data) -> Data in
        try wrap {
          let result = try ref.handshake.writeMessage(payload: payload)
          ref.handshakeHash = result.handshakeHash
          ref.transport = result.transport
          return result.message
        }
      }
      Function("readMessage") { (ref: HandshakeObject, message: Data) -> Data in
        try wrap {
          let result = try ref.handshake.readMessage(message)
          ref.handshakeHash = result.handshakeHash
          ref.transport = result.transport
          return result.payload
        }
      }
      Function("handshakeHash") { (ref: HandshakeObject) -> Data? in ref.handshakeHash }
      Function("takeTransport") { (ref: HandshakeObject) -> TransportObject? in
        guard let transport = ref.transport else { return nil }
        ref.transport = nil
        return TransportObject(transport)
      }
      Function("remoteStaticPublicKey") { (ref: HandshakeObject) -> Data? in try wrap { try ref.handshake.remoteStaticPublicKey } }
      Function("close") { (ref: HandshakeObject) in ref.handshake.close() }
      Function("setFixedEphemeral") { (ref: HandshakeObject, privateKey: Data) in try wrap { try ref.handshake.setFixedEphemeral(privateKey) } }
    }

    Class(TransportObject.self) {
      Function("writeMessage") { (ref: TransportObject, payload: Data) -> Data in try wrap { try ref.transport.writeMessage(payload: payload) } }
      Function("readMessage") { (ref: TransportObject, message: Data) -> Data in try wrap { try ref.transport.readMessage(message) } }
      Function("rekeySend") { (ref: TransportObject) in try wrap { try ref.transport.rekeySend() } }
      Function("rekeyReceive") { (ref: TransportObject) in try wrap { try ref.transport.rekeyReceive() } }
      Function("setSendNonce") { (ref: TransportObject, nonce: Double) in try wrap { try ref.transport.setSendNonce(try nonceValue(nonce)) } }
      Function("setReceiveNonce") { (ref: TransportObject, nonce: Double) in try wrap { try ref.transport.setReceiveNonce(try nonceValue(nonce)) } }
      Function("close") { (ref: TransportObject) in ref.transport.close() }
    }
  }
}

/// JavaScript numbers arrive as doubles.
private func nonceValue(_ nonce: Double) throws -> UInt64 {
  guard nonce >= 0, nonce == nonce.rounded(.down), nonce <= 9_007_199_254_740_991 else {
    throw TorannError.invalidArgument("The nonce must be an integer from 0 to 2^53 - 1.")
  }
  return UInt64(nonce)
}

/// An error other than a `TorannError` becomes `hostFailure` carrying only its type
/// name, so that no foreign message reaches JavaScript.
private func wrap<T>(_ body: () throws -> T) throws -> T {
  do {
    return try body()
  } catch let error as TorannError {
    throw TorannException(code: code(error), reason: error.message)
  } catch let error as Exception {
    throw error
  } catch {
    throw TorannException(code: "hostFailure", reason: String(describing: type(of: error)))
  }
}

private func code(_ error: TorannError) -> String {
  switch error {
  case .invalidProtocolName: return "invalidProtocolName"
  case .unsupportedFunction: return "unsupportedFunction"
  case .invalidArgument: return "invalidArgument"
  case .invalidState: return "invalidState"
  case .authenticationFailed: return "authenticationFailed"
  case .closed: return "closed"
  }
}
