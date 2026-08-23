<!-- Copyright © 2026 Stony Grey LLC. SPDX-License-Identifier: MIT -->

# Torann

Torann is a C# implementation of the
[Noise Protocol Framework](https://noiseprotocol.org/noise.html)
(revision 34). There is no libsodium and no native binary. The package
targets `net9.0` and runs on iOS and Android.

The name is Irish for noise (and thunder).

This code is not production ready. It has not been independently audited. Development used Fable 5 and Grok 4.6.

## What it implements

Handshake patterns: `NN`, `NK`, `KK`, `XX`, `IK`, with `psk0`–`pskN`
modifiers. Other patterns (`N`, `X`, `K`, deferred variants, `448`)
are rejected by `Protocol.Parse`.

- **DH**: `25519` (X25519 via Bouncy Castle's managed implementation)
- **Ciphers**: `ChaChaPoly`, `AESGCM`. AES-GCM uses
  `System.Security.Cryptography` (OS-backed). ChaChaPoly uses the OS
  where it exists and Bouncy Castle where it does not (e.g. Android
  API &lt; 28)
- **Hashes**: `SHA256`, `SHA512`

Correctness is checked against the
[cacophony](https://github.com/haskell-cryptography/cacophony)
reference vectors (public domain / Unlicense). Every vector whose
protocol Torann supports is run; the rest (448, BLAKE2, one-way and
deferred patterns) are skipped. RFC 7748 X25519 vectors are in
`tests/Torann.Tests`.

## Usage

```csharp
using Torann;

var protocol = Protocol.Parse("Noise_XX_25519_ChaChaPoly_SHA256");
using var staticKey = protocol.GenerateKeyPair();   // persist PrivateKey for reuse

using var handshake = protocol.CreateHandshake(initiator: true, s: staticKey);

var message = new byte[Protocol.MaxMessageLength];  // 65535
var (length, _, _) = handshake.WriteMessage(payload: default, message);
// send message[..length]; read the peer's reply with handshake.ReadMessage(...)
// the final handshake message returns a Transport:
// var (_, handshakeHash, transport) = handshake.ReadMessage(...);
// transport.WriteMessage(...) / transport.ReadMessage(...) for application data
```

`XX` is the first-contact pattern (static keys are exchanged and
proven during the handshake). `IK` and `KK` skip that exchange when
the initiator already knows the responder's static public key.

`CreateHandshake` takes an optional prologue (bound into the
transcript) and optional 32-byte PSKs, one per `pskN` modifier.

Dispose `HandshakeState`, `Transport`, and `KeyPair`. Encrypt or
decrypt after dispose throws `ObjectDisposedException`. It does not
fail open to plaintext.

A decrypt or DH error during the handshake is terminal. Discard the
`HandshakeState`. Do not pin `RemoteStaticPublicKey` unless the
handshake returned a `Transport`.

Transport encrypt/decrypt is serialized internally. A lost write still
desynchronizes nonces (Noise uses a strict counter). Abort the session
on decrypt failure. `RekeySend` / `RekeyReceive` implement Noise
§11.3.

## Crypto

AEAD and hashes use OS-validated implementations (CryptoKit on
Apple platforms, Conscrypt/OpenSSL on Android/Linux, CNG on Windows)
when the platform supplies them.

X25519 and the ChaChaPoly fallback are managed Bouncy Castle. Managed
code offers weaker constant-time and memory-hygiene guarantees than
libsodium. The ChaChaPoly fallback key (Android API &lt; 28) is
GC-lifetime: Bouncy Castle's `KeyParameter` clones on construct and
on `GetKey()`, and has no public wipe API.

This library has not been independently audited.

## License

MIT. See [LICENSE](LICENSE).