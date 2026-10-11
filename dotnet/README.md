<!-- Copyright © 2026 Stony Grey LLC. SPDX-License-Identifier: MIT -->

# Torann for .NET

Torann is a C# implementation of the [Noise Protocol Framework](https://noiseprotocol.org/noise.html), revision 34. The package contains managed code only, with no native binary such as libsodium or OpenSSL, so it runs wherever .NET runs, including iOS and Android. It targets `net9.0`. The repository README at https://github.com/stonygrey/torann explains Noise, describes how the API is used, and lists the other Torann packages, which share the same API.

## Functions

The Diffie-Hellman functions are `25519` and `448`, which are X25519 and X448 through Bouncy Castle's managed code. The ciphers are `ChaChaPoly` and `AESGCM`. AES-GCM comes from `System.Security.Cryptography`, which is backed by the operating system. ChaCha20-Poly1305 comes from the operating system where it exists and from Bouncy Castle on Android below API 28. The hashes are `SHA256`, `SHA512`, `BLAKE2s`, and `BLAKE2b`. The two BLAKE2 hashes come from Bouncy Castle and use the HMAC construction the specification requires, not BLAKE2's own keyed mode.

## Installation

```
dotnet add package Torann
```

## Usage

```csharp
using Torann;

var protocol = NoiseProtocol.Parse("Noise_XX_25519_ChaChaPoly_SHA256");
using var staticKey = protocol.GenerateKeyPair();   // persist PrivateKey for reuse

using var handshake = protocol.CreateHandshake(initiator: true, s: staticKey);

var message = new byte[NoiseProtocol.MaxMessageLength];  // 65535
var (length, _, _) = handshake.WriteMessage(payload: default, message);
// send message[..length]; read the peer's reply with handshake.ReadMessage(...)
// the final handshake message returns a Transport:
// var (_, handshakeHash, transport) = handshake.ReadMessage(...);
// transport.WriteMessage(...) / transport.ReadMessage(...) for application data
```

The C# API follows .NET conventions where they differ from the other packages. `WriteMessage` and `ReadMessage` write into a buffer the caller supplies and return the number of bytes written, and the handshake versions return a tuple with the handshake hash and the transport, which are null until the final message. The local static key pair is the `s` argument of `CreateHandshake`, and the pre-shared keys are any `IEnumerable<byte[]>`. The six error categories map to .NET exception types: `ArgumentException` for an invalid protocol name or argument, `NotSupportedException` for an unsupported function, `InvalidOperationException` for an invalid state, `CryptographicException` for an authentication failure, and `ObjectDisposedException` after dispose.

Dispose every `HandshakeState`, `Transport`, and `KeyPair`. Transport encrypt and decrypt are serialized by a lock inside the object, so two threads may call into one transport, but a call must not be held across an `await`. `RekeySend` and `RekeyReceive` rekey one direction, and `SetSendNonce` and `SetReceiveNonce` set the counter of one direction.

## Crypto

The AEAD ciphers and the hashes use the implementations the operating system validates, which are CryptoKit on Apple platforms, Conscrypt and OpenSSL on Android and Linux, and CNG on Windows, when the platform supplies them.

X25519, X448, BLAKE2, and the ChaCha20-Poly1305 fallback are managed Bouncy Castle code. Managed code gives weaker guarantees than libsodium about constant-time execution and about scrubbing memory. The key of the ChaCha20-Poly1305 fallback, which is used on Android below API 28, lives as long as the garbage collector allows, because Bouncy Castle's `KeyParameter` clones the key on construction and again on `GetKey()` and has no public wipe operation. The library zeros its own key arrays with `CryptographicOperations.ZeroMemory`.

The X25519 and X448 functions call Bouncy Castle's `CalculateAgreement`, which returns false for a low-order peer key, and the library then throws `CryptographicException` with the message `The peer's public key is invalid.`

## Tests

`dotnet test dotnet/Torann.slnx` runs all 1,352 shared vectors with none skipped, the security tests, and the key derivation and shared secret examples of RFC 7748 §6.1 and §6.2 in `Rfc7748Tests`. The test project reaches the fixed-ephemeral entry point through `InternalsVisibleTo`.
