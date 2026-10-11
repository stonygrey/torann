<!-- Copyright © 2026 Stony Grey LLC. SPDX-License-Identifier: MIT -->

# Torann

Torann is an implementation of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html) for mobile applications. Noise, at revision 34 of its specification, is a framework for building authenticated key exchange protocols. Two parties exchange a small number of handshake messages, each carrying Diffie-Hellman public keys and, where the pattern allows, an encrypted payload. When the handshake completes, both parties hold the same pair of symmetric keys and use them to encrypt everything they send afterwards. Torann is five packages, one per language, which share one API, one set of test vectors, and one version number. The name is Irish for noise, and also for thunder.

| Package | Language | Platforms | Functions | Install |
|---|---|---|---|---|
| `Torann` on NuGet | C# (`dotnet/`) | `net9.0`, including iOS and Android through .NET | `25519`, `448`, `ChaChaPoly`, `AESGCM`, `SHA256`, `SHA512`, `BLAKE2s`, `BLAKE2b` | `dotnet add package Torann` |
| `Torann` Swift package | Swift (`swift/`, manifest at the repository root) | iOS 18 and later, macOS 15 and later | `25519`, `ChaChaPoly`, `AESGCM`, `SHA256`, `SHA512` | `.package(url: "https://github.com/stonygrey/torann.git", from: "0.3.1")` |
| `com.stonygrey:torann` on Maven Central | Kotlin (`kotlin/`) | Android 13 (API 33) and later, JVM 11 and later | `25519`, `448`, `ChaChaPoly`, `AESGCM`, `SHA256`, `SHA512`, `BLAKE2s`, `BLAKE2b` | `implementation("com.stonygrey:torann:0.3.1")` |
| `torann` on pub.dev | Dart (`flutter/torann/`) | Flutter on iOS 18 and Android 13 (API 33) and later | the Swift set on iOS, the Kotlin set on Android | `torann: ^0.3.1` |
| `@stonygrey/torann` on npm | TypeScript (`reactnative/torann/`) | React Native, as an Expo module, on iOS 18 and Android 13 (API 33) and later | the Swift set on iOS, the Kotlin set on Android | `npm install @stonygrey/torann` |

A Noise protocol is named by its handshake pattern and its three cryptographic functions, for example `Noise_XX_25519_ChaChaPoly_SHA256`. The handshake pattern is the sequence of messages the two parties exchange and the Diffie-Hellman operations each message performs. The specification defines 38 of them: 3 one-way patterns, in which only the initiator sends; 12 fundamental interactive patterns; and 23 deferred patterns, which move some Diffie-Hellman operations to a later message. Every package implements all 38, and every pattern accepts the `psk` modifiers, which mix a 32-byte pre-shared key into the handshake at a chosen message. The three functions are the Diffie-Hellman function, the cipher, and the hash. The Functions column of the table lists which each package supports; parsing a name that asks for a function the platform lacks fails with an unsupported-function error, so an application that runs on both iOS and Android uses `25519` with `SHA256` or `SHA512`. The one omission is the `fallback` modifier, because neither reference vector suite covers it, and an implementation without vectors could not be checked against anything.

Each package has its own README with installation, usage, and a Crypto section that states what the platform's cryptography library holds and what the package can and cannot wipe: `dotnet/README.md`, `swift/README.md`, `kotlin/torann/README.md`, `flutter/torann/README.md`, and `reactnative/torann/README.md`. The Flutter plugin and the React Native package contain no cryptography of their own. Each wraps the Swift implementation on iOS and the Kotlin implementation on Android. `readme/torann-api.md` is the language-neutral specification of the API and of its behavior, and it is where the exact error messages, limits, and the differences between the implementations are recorded.

This code is not production ready. It has not been independently audited.

## Usage

The API is the same four types in every language. A protocol is the parsed name of a Noise protocol and is the factory for the other three. A key pair holds a Diffie-Hellman private key and its public key. A handshake state runs one handshake. A transport encrypts and decrypts application messages once the handshake is complete. In Swift:

```swift
import Torann

let proto = try NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_SHA256")
let staticKey = try proto.generateKeyPair()
let handshake = try proto.createHandshake(initiator: true, localStatic: staticKey)
let first = try handshake.writeMessage()         // send first.message
// read the peer's reply with handshake.readMessage(reply); the final message's result
// carries handshakeHash and transport, and transport.writeMessage / readMessage carry
// application data
```

The same sequence in C# is in `dotnet/README.md`, in Kotlin in `kotlin/torann/README.md`, in Dart in `flutter/torann/README.md`, and in TypeScript in `reactnative/torann/README.md`. The names of the operations differ only in each language's conventions, and the rest of this section uses the Swift spelling.

`XX` is the pattern for a first contact. Each side sends its static public key during the handshake and proves that it holds the matching private key. `IK` and `KK` skip that exchange when the initiator already knows the responder's static public key, for example from an earlier `XX` handshake. `NN` uses no static keys and authenticates neither party. The one-way patterns `N`, `K`, and `X` consist of a single message and produce a transport that carries data from the initiator to the responder only; a call in the reverse direction fails with an invalid-state error.

A handshake is created from the protocol with an initiator flag and up to four optional inputs. The local static key pair is required when the pattern sends or pre-shares this party's static key. The remote static public key is required when the pattern pre-shares the peer's key, as `IK`, `KK`, and the one-way patterns do. The prologue is data that both parties must agree on; it is mixed into the handshake hash and never transmitted, so a mismatch makes the handshake fail. The pre-shared keys are 32 bytes each, one per `psk` modifier, in the order the modifiers appear in the pattern. The handshake copies every input, so the caller may close the key pair or zero its own arrays afterwards.

The two parties then alternate. The initiator writes the first message, the responder reads it and writes the second, and so on. Each write returns the message to send, and each read returns the payload the peer attached. The result of the final message also carries the handshake hash, which both sides hold and which an application can use to bind other data to the session, and the transport. A payload written before the handshake has derived a cipher key is sent in clear, as Noise defines; the payload of the first `XX` message is an example.

A key pair is the only object that holds a long-lived private key. An application that reuses a static key stores the private key bytes it reads from the key pair and later recreates the key pair from them. Public keys, messages, and payloads are returned as copies that the caller owns.

Each transport message is the ciphertext followed by a 16-byte authentication tag, so a payload may be at most 65519 bytes and a message at most 65535. Noise numbers the messages in each direction with a strict counter, the nonce, so a message lost or reordered in transit leaves the two sides with different counters and every later decrypt fails. The application discards the transport on a decrypt failure, because Noise leaves session termination to the application. Rekey replaces the key of one direction without resetting its counter, and both sides must rekey the same direction at the same point in the message sequence. For a transport that delivers messages out of order, the nonce of each direction can be set explicitly, and replay protection is then the application's responsibility.

Every error belongs to one of six categories: invalid protocol name, unsupported function, invalid argument, invalid state, authentication failed, and closed. The category is what an application branches on. The message is for logs and never contains key material. Each language spells the categories in its own way, which its README gives.

Every key pair, handshake, and transport has an explicit close, which is `Dispose` in C# and `close()` elsewhere. Close zeros the key material the library owns. After close every operation fails; nothing continues without encryption. A decrypt or Diffie-Hellman failure during a handshake is terminal: the handshake refuses every later call and must be discarded, because a message that fails to authenticate means the two parties no longer agree on the session. Do not pin the peer's static public key unless the handshake returned a transport, because the key is authenticated only by the Diffie-Hellman operations that follow it.

## Crypto

No package implements a cipher, a hash, or curve arithmetic of its own. Each implements only the Noise constructions on top of the platform's primitives: the HKDF variant of Noise §4.3, which is the key derivation function Noise builds from HMAC; the nonce layouts of §12.3 and §12.4, which say how the message counter is placed in the cipher's nonce; the rekey function of §11.3; and the handshake state machine. Each package README lists which platform library supplies each primitive.

Three terms recur in those sections. An AEAD cipher encrypts a message and also produces a 16-byte authentication tag that lets the receiver detect any change to the ciphertext; every Noise message carries one once a cipher key exists. A low-order public key is one of a handful of X25519 or X448 values for which the Diffie-Hellman output is all zeros whatever the private key, so a peer that sends one would know the shared secret in advance; every package rejects such a key and treats it as a terminal handshake failure. Key hygiene means zeroing secret bytes once they are no longer needed. Every package zeros the key material it owns, which is the static and ephemeral private keys, the chaining key, the pre-shared keys, and the cipher keys, when the handshake completes and on close. What no package can zero is the copies the platform's cryptography library and the language runtime keep, and each Crypto section states those limits for its platform.

## Tests

A test vector is a complete recorded session in which every key is fixed, including the ephemeral keys that an implementation would normally draw at random, so that an implementation can be compared byte for byte with the implementations that produced the recording. The shared vectors in `vectors/` come from two other Noise implementations, 944 from cacophony and 408 from snow. Every implementation's tests run them: all 1,352 in C# and Kotlin, and the 440 that use the Swift function set in Swift and on iOS. Because the vectors prescribe each party's ephemeral key, every package has a test-only entry point that sets it. That entry point is kept out of the normal import path, as a separate `testing` module in Dart and TypeScript, behind an opt-in annotation in Kotlin, and as internal access in Swift and C#, and application code must not use it.

The vectors fix every key, so they never exercise key generation. `interop/run.py` covers that gap. It completes live handshakes with freshly generated keys between every ordered pair of the C#, Swift, and Kotlin implementations, 588 runs across seven patterns. The key derivation examples of RFC 7748 §6.1 and §6.2, the document that defines X25519 and X448, run in every implementation's tests, and the shared-secret examples run in the C# and Swift tests, where the Diffie-Hellman function is reachable directly.

## Repository layout

```
Package.swift           Swift package manifest (SwiftPM requires it at the root)
swift/                  Swift implementation and tests
kotlin/                 Gradle build: torann, torann-testkit, android-tests, interop-driver
flutter/torann/         Flutter plugin over the Swift and Kotlin implementations
reactnative/torann/     React Native package (Expo module) over the Swift and Kotlin implementations
dotnet/                 C# library, tests, interop driver, and NuGet scripts
vectors/                Shared test vectors (read-only copies of the upstream files)
interop/                Cross-language interop runner
lib/                    Support
readme/                 torann-api.md (the API specification) and vectors.md (the vector runner)
```

## License

MIT. See [LICENSE](LICENSE). The vector files keep their upstream licenses, which `vectors/README.md` describes.
