<!-- Copyright © 2026 Stony Grey LLC. SPDX-License-Identifier: MIT -->

# Torann

Torann is a C# implementation of the
[Noise Protocol Framework](https://noiseprotocol.org/noise.html)
(revision 34). There is no libsodium and no native binary. The package
targets `net9.0` and runs on iOS and Android.

The name is Irish for noise (and thunder).

This code is not production ready. It has not been independently audited.

The impetus for Torann came from [BlueConnect](https://github.com/stonygrey/BlueConnect) and beyond the included test vectors, that is the extent to which Torann has been tested.

## What it implements

Every handshake pattern the Noise specification defines: the one-way
patterns (`N`, `K`, `X`), the twelve fundamental interactive patterns
(`NN` through `IX`), and the twenty-three deferred patterns (`NK1`,
`X1X1`, …), all with `psk0`–`pskN` modifiers. One-way patterns produce
a one-directional `Transport`; the reverse direction throws. The
`fallback` modifier (Noise Pipes) is the one omission — neither
reference suite carries vectors for it.

- **DH**: `25519`, `448` (X25519/X448 via Bouncy Castle's managed
  implementations)
- **Ciphers**: `ChaChaPoly`, `AESGCM`. AES-GCM uses
  `System.Security.Cryptography` (OS-backed). ChaChaPoly uses the OS
  where it exists and Bouncy Castle where it does not (e.g. Android
  API &lt; 28)
- **Hashes**: `SHA256`, `SHA512`, `BLAKE2s`, `BLAKE2b` (BLAKE2 via
  Bouncy Castle, HMAC construction per the spec)

Correctness is checked against the complete
[cacophony](https://github.com/haskell-cryptography/cacophony)
reference suite (944 vectors, public domain / Unlicense) and
[snow](https://github.com/mcginty/snow)'s suite including its
multi-psk vectors (408 vectors, MIT/Apache-2.0) — every vector in
both files runs; none are skipped. RFC 7748 X25519 vectors are in
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