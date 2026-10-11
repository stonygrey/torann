<!-- Copyright © 2026 Stony Grey LLC. SPDX-License-Identifier: MIT -->

# Torann API specification

## Purpose

This document specifies the public API and the observable behavior of the five Torann implementations: C#, Swift, Kotlin, Dart, and TypeScript. Where two implementations behave differently on purpose, the section "Differences between the implementations" says so.

## Reference documents

- The Noise Protocol Framework, revision 34 (https://noiseprotocol.org/noise.html). Section numbers in this document refer to that revision.
- RFC 7748, Elliptic Curves for Security, which defines X25519 and X448.
- RFC 8439, ChaCha20 and Poly1305 for IETF Protocols.
- `readme/vectors.md`, how a vector runner maps the shared vectors onto this API.
- `vectors/README.md`, the provenance and format of the shared vectors.

## Definitions

- **DH**: the Diffie-Hellman function of a protocol. Noise names X25519 `25519` and X448 `448`. Swift supports `25519` only; Kotlin and C# support both.
- **AEAD**: authenticated encryption with associated data. Noise uses ChaCha20-Poly1305 (`ChaChaPoly`) and AES-256-GCM (`AESGCM`). Both produce a 16-byte authentication tag.
- **Pattern**: a Noise handshake pattern such as `XX`, made of pre-message tokens and message patterns (Noise §7).
- **Token**: one element of a message pattern: `e`, `s`, `ee`, `es`, `se`, `ss`, or `psk`.
- **PSK**: a 32-byte pre-shared symmetric key, one per `psk` modifier in the protocol name (Noise §9).
- **Prologue**: application data that both parties mix into the handshake hash before the first message. It is authenticated but not transmitted (Noise §6).
- **Handshake hash**: the value `h` of the SymmetricState when the handshake completes, usable for channel binding (Noise §11.2).
- **CipherState**: an AEAD key `k` with a 64-bit nonce counter `n` (Noise §5.1).
- **Split**: the derivation of the two transport CipherStates from the chaining key when the last handshake message is processed (Noise §5.2).
- **Terminal failure**: a failure after which a handshake object refuses every further write and read.

## Types

Torann has four public types. A **protocol** is a parsed protocol name that acts as a factory for key pairs and handshakes. A **key pair** holds a DH private key and its public key. A **handshake state** runs one handshake and produces a **transport**, which encrypts and decrypts application messages after the handshake. The names are `NoiseProtocol`, `KeyPair`, `HandshakeState`, and `Transport` in every implementation. The section "Naming" gives each language's spelling of the operations.

Every byte sequence crosses the API as a plain byte array: `Data` in Swift, `ByteArray` in Kotlin, `Uint8List` in Dart, `Uint8Array` in TypeScript, and `ReadOnlySpan<byte>` or `byte[]` in C#. The library never interprets bytes as text.

## Protocol

### Parsing

A protocol is created only by parsing a name. The name has the form `Noise_<pattern><modifiers>_<dh>_<cipher>_<hash>`, for example `Noise_XXpsk3_25519_ChaChaPoly_SHA256`. The parser splits the name on `_` and requires exactly five parts, the first being `Noise`. Anything else, including an empty name, is an **InvalidProtocolName** error with the message `'<name>' is not a valid Noise protocol name.`

The second part is the pattern name followed by optional modifiers. The pattern name is the longest prefix of upper-case ASCII letters and ASCII digits. The digits occur in the deferred patterns, such as `NK1` and `X1X1`. The remainder is a list of modifiers separated by `+`. The only modifiers Torann supports are `psk0`, `psk1`, and so on. The `fallback` modifier is not supported, because neither vector suite covers it.

The parser checks the parts in this order and reports the first failure as an **UnsupportedFunction** error with the message shown:

| Check | Message |
|---|---|
| Pattern name is one of the 38 patterns in the section "Patterns" | `Handshake pattern '<pattern>' is not supported.` |
| Each modifier is `psk<N>` with `N` a decimal integer of ASCII digits, `N >= 0` | `Pattern modifier '<modifier>' is not supported.` |
| Each `psk<N>` fits the pattern: `N` is 0, or `1 <= N <= number of messages` | `psk<N> is out of range for pattern <pattern>.` |
| DH function is supported | `DH function '<dh>' is not supported.` |
| Cipher function is supported | `Cipher function '<cipher>' is not supported.` |
| Hash function is supported | `Hash function '<hash>' is not supported.` |

`psk0` inserts a `psk` token at the start of the first message. `pskN` for `N >= 1` appends a `psk` token to message `N`. Several `psk` modifiers may be combined, as in `NXpsk0+psk1+psk2`, and are applied in the order written. The parsed protocol records the number of PSKs the handshake needs, which is the number of `psk` modifiers.

The parsed protocol exposes its full name as `name`, exactly as passed in.

### Constants

`maxMessageLength` is 65535, the maximum length in bytes of any Noise handshake or transport message (Noise §3). It is a constant on the protocol type.

### Key pairs

`generateKeyPair()` draws random bytes of the DH key length, which is 32 for `25519` and 56 for `448`, from the platform's cryptographic random number generator, and derives the public key with the DH function's base-point multiplication. The source of randomness is `RandomNumberGenerator.Fill` in C#, CryptoKit's own key generation in Swift, and `java.security.SecureRandom` in Kotlin. The call returns a key pair.

`createKeyPair(privateKey)` derives the public key from a caller-supplied private key and returns a key pair. The private key must be exactly the DH key length, 32 bytes for `25519` and 56 bytes for `448`; any other length is an **InvalidArgument** error with the message `The private key must be <length> bytes.` Every value of that length is a valid private key. The clamping that RFC 7748 defines happens inside the DH function at the time of use, and the stored private key bytes are not modified. This matters for the vectors, which supply unclamped private keys such as `893e28b9…`. CryptoKit, and Bouncy Castle as used by both the C# and the Kotlin implementation, derive the same public key `ca35def5…` from that value.

### Creating a handshake

`createHandshake(initiator, prologue, localStatic, remoteStatic, psks)` creates a handshake state. `initiator` is true for the party that sends the first message. `prologue` defaults to empty. `localStatic` is this party's static key pair. `remoteStatic` is the peer's static public key. `psks` is the list of PSKs and defaults to empty. The handshake consumes one PSK per `psk` token, in the order the tokens occur in the pattern. That is handshake processing order, which differs from the order the modifiers are written only when they are written out of order, as in `NXpsk2+psk0`. The handshake copies the private key out of `localStatic`, copies `remoteStatic`, and copies each PSK, so closing the key pair or zeroing the caller's arrays after this call does not affect the handshake.

The call validates its arguments in this order and raises the first failure as an **InvalidArgument** error:

| Check | Message |
|---|---|
| Every PSK is 32 bytes | `Pre-shared keys must be 32 bytes.` |
| The PSK count equals the number of `psk` modifiers | `The protocol requires <n> pre-shared key(s); <m> were provided.` |
| `localStatic` is present when the pattern sends or pre-shares this party's static key | `A local static key is required by the handshake pattern.` |
| `remoteStatic` is present when the pattern pre-shares the peer's static key | `The remote static public key is required by the handshake pattern.` |
| `remoteStatic` has the DH key length | `Remote static public key must be <length> bytes.` |

A party "sends" its static key when any message pattern that party writes contains an `s` token. A party's static key is "pre-shared" when the pattern's pre-message for that party contains `s`. A `localStatic` or `remoteStatic` that the pattern does not need is accepted and ignored. Reading the keys of a closed key pair raises **Closed**, so passing a closed key pair as `localStatic` raises **Closed**.

After validation the handshake initializes the SymmetricState from the protocol name (Noise §5.2), mixes the prologue into the hash, and then mixes the pre-message public keys, initiator first then responder (Noise §7.1).

## Key pair

A key pair exposes `privateKey` and `publicKey`, each of the DH key length (32 bytes for `25519`, 56 bytes for `448`). Every implementation returns a copy on every read. `close()` zeros the private key bytes the library owns and marks the key pair closed. After `close()`, reading either key raises **Closed**. Calling `close()` twice has no further effect.

A key pair is the only object that holds a long-lived private key, so an application that reuses a static key stores the bytes from `privateKey` and later calls `createKeyPair`.

## Handshake state

### Turns

A handshake alternates between the two parties, starting with the initiator. The handshake state tracks whose turn it is. `writeMessage` when it is the peer's turn raises **InvalidState** with the message `It is not this party's turn to write a message.` `readMessage` when it is this party's turn to write raises **InvalidState** with `It is not this party's turn to read a message.` These checks happen before any state changes, and the handshake remains usable.

### writeMessage

`writeMessage(payload)` produces the next handshake message. `payload` defaults to empty. The message is the bytes each token produces, in order, followed by the payload. An `e` token produces a public key of the DH key length. An `s` token produces a public key, plus a 16-byte tag when a cipher key exists at that point. The `psk` and DH tokens produce nothing. The payload is followed by a 16-byte tag when a cipher key exists after the tokens. Payloads written before the handshake has derived a cipher key are sent in clear, as Noise defines (for example the payload of the first `NN` message).

The call computes the message length before doing anything else. If it exceeds 65535 the call raises **InvalidArgument** with `A Noise message must not exceed 65535 bytes.` and the handshake remains usable, because the message pattern has not been consumed. The test `OversizedHandshakePayloadDoesNotConsumeTheMessagePattern` and its Swift and Kotlin counterparts check this.

The result carries the message bytes and, on the final message of the pattern only, the handshake hash and the transport. On every earlier message both are absent.

### readMessage

`readMessage(message)` consumes the peer's next message. A message longer than 65535 bytes raises **InvalidArgument** with `A Noise message must not exceed 65535 bytes.` and the handshake remains usable. The call then computes the minimum length of the expected message, which is the token bytes described above plus 16 for the payload tag when a cipher key will exist, and raises **AuthenticationFailed** with `The handshake message is truncated.` when the message is shorter. This check also runs before the message pattern is consumed, in every implementation, so the handshake remains usable after it.

The call then processes the tokens, decrypts the payload, and returns the payload bytes and, on the final message only, the handshake hash and the transport. A failure in this part is terminal (see "Terminal failure").

### Terminal failure

Once `writeMessage` or `readMessage` has consumed a message pattern, any failure marks the handshake failed. The failures that can occur there are an AEAD authentication failure when decrypting an `s` token or the payload (**AuthenticationFailed**), and a DH failure (see "Low-order public keys"). After a terminal failure every `writeMessage` and `readMessage` raises **InvalidState** with `The handshake has failed and must be discarded.` and `remoteStaticPublicKey` returns null. The test `TamperedHandshakeReadIsTerminal` and its Swift and Kotlin counterparts check this.

### Completion

When the final message pattern is consumed, the handshake computes the handshake hash, calls Split to derive the two transport CipherStates, and zeros its own secrets: the chaining key, the handshake CipherState key, the local static private key, the ephemeral private key, and any remaining PSKs. The result carries the handshake hash and the transport. The handshake hash has the hash output length: 32 bytes for `SHA256` and `BLAKE2s`, 64 bytes for `SHA512` and `BLAKE2b`.

After completion `writeMessage` and `readMessage` raise **InvalidState** with `The handshake is already complete.` `remoteStaticPublicKey` still returns the peer's static key, so an application reads it after completion and before `close()` when it wants to pin the key. The transport is independent of the handshake state: closing the handshake does not close the transport.

### remoteStaticPublicKey

`remoteStaticPublicKey` returns a copy of the peer's static public key, or null. A key passed as `remoteStatic` to `createHandshake` is available at once. A key learned from the peer becomes available after the `readMessage` call that carried it returns successfully (for `XX`, after the initiator reads message 2). The value is null after a terminal failure, even when the key had been learned earlier. Reading it after `close()` raises **Closed**. The tests `RemoteStaticPublicKeyIsAvailableAfterSuccessfulXxMessage2` and `TamperedHandshakeReadIsTerminal`, and their Swift and Kotlin counterparts, check this. An application does not pin a learned key unless the handshake returned a transport, because the key is authenticated only by the DH operations that follow it.

### close

`close()` zeros the local static private key, the ephemeral private key, the PSKs, the chaining key, and the handshake CipherState key, and marks the handshake closed. After `close()` every operation, including `remoteStaticPublicKey`, raises **Closed**. Calling `close()` twice has no further effect. The C# test `MidHandshakeDisposeThenWriteDoesNotEmitStaticKey` and the Swift and Kotlin tests `midHandshakeCloseThenWriteThrows` check that a write after close emits nothing.

## Transport

### Directions

A transport has a send CipherState and a receive CipherState. For interactive patterns the initiator sends with the first CipherState from Split and receives with the second, and the responder does the reverse (Noise §5.2). For the one-way patterns `N`, `K`, and `X` (Noise §7.4) only the first CipherState is used: the initiator can only send and the responder can only receive. On the responder, `writeMessage`, `rekeySend`, and `setSendNonce` raise **InvalidState** with `A one-way pattern's responder cannot send transport messages.` On the initiator, `readMessage`, `rekeyReceive`, and `setReceiveNonce` raise **InvalidState** with `A one-way pattern's initiator cannot receive transport messages.` The test `OneWayTransportRejectsTheReverseDirection` and its Swift and Kotlin counterparts check this.

### writeMessage and readMessage

`writeMessage(payload)` encrypts the payload with the send CipherState and empty associated data, and returns the ciphertext followed by the 16-byte tag. The payload may be at most 65519 bytes (65535 minus the tag); a longer payload raises **InvalidArgument** with `The payload must not exceed 65519 bytes.` The send nonce increases by one after a successful encryption and is unchanged after a failure.

`readMessage(message)` decrypts a message with the receive CipherState and returns the payload. A message longer than 65535 bytes raises **InvalidArgument** with `A Noise message must not exceed 65535 bytes.` A message shorter than 16 bytes raises **AuthenticationFailed** with `Ciphertext is shorter than the authentication tag.` A tag mismatch raises **AuthenticationFailed** with the fixed message `The authentication tag did not match.`, so that no provider text crosses the API. The receive nonce increases by one after a successful decryption and is unchanged after a failure. A failed decryption does not close or fail the transport, because the Noise specification leaves session termination to the application (Noise §11.1 and §13); the application discards the transport, as the root `README.md` instructs.

The checks run in this order: closed, length, direction, nonce exhaustion, then the AEAD operation.

### Nonces

Each CipherState has a 64-bit unsigned nonce counter starting at zero after Split. The nonce is encoded as 4 zero bytes followed by the 64-bit counter: little-endian for `ChaChaPoly` (Noise §12.3) and big-endian for `AESGCM` (Noise §12.4). The value 2^64 − 1 is reserved (Noise §5.1). When a CipherState's nonce reaches 2^64 − 1, encrypt and decrypt raise **InvalidState** with `Nonce exhausted; the session must be re-established.`

`setSendNonce(nonce)` and `setReceiveNonce(nonce)` set the counter of the respective CipherState. They exist for out-of-order transports (Noise §11.4), where the application carries the nonce alongside each message. Setting 2^64 − 1 raises **InvalidArgument** with `Nonce 2^64-1 is reserved.` The library does not track which nonces were used, so setting an earlier nonce lets a previous ciphertext decrypt again. The test `SetReceiveNonceAllowsReplayOfAPreviousCiphertext` and its Swift and Kotlin counterparts record this. Replay protection belongs to the application.

### Rekey

`rekeySend()` and `rekeyReceive()` replace the key of the respective CipherState with `REKEY(k)`, which Noise §4.2 defines as the first 32 bytes of `ENCRYPT(k, 2^64 − 1, empty, 32 zero bytes)`. The nonce is not reset (Noise §11.3). Both parties must rekey the matching direction at the same point in the message sequence. The test `RekeyRotatesTransportKeysWithoutResettingNonces` and its Swift and Kotlin counterparts show that a message written after `rekeySend` fails to decrypt until the peer calls `rekeyReceive`. The test `RekeyMatchesTheSpecDefinition`, present in the C#, Swift, and Kotlin suites, checks the derivation against the formula directly, because no vector suite carries rekey vectors.

### close

`close()` zeros both CipherState keys that the library owns and marks the transport closed. After `close()` every operation raises **Closed**, and no plaintext is written anywhere. Calling `close()` twice has no further effect. The C# test `TransportWriteAfterDisposeThrowsAndDoesNotEmitPlaintext` and the Swift and Kotlin tests `transportWriteAfterCloseThrows` check this.

## Thread safety

In C#, every public method and property of `HandshakeState` and `Transport` runs under a per-object lock, so two threads calling into the same object are serialized. `KeyPair` and `NoiseProtocol` have no lock; a protocol is immutable, and a key pair is only read until it is closed. The Swift implementation keeps each object's state inside a `Mutex` from the Synchronization module, which needs iOS 18 or later, so every operation runs under the lock and the four public types are `Sendable`. The one `@unchecked Sendable` annotation is on the private state struct inside `Transport`, because its two CipherStates are class instances, and they are reached only through the mutex. The Kotlin implementation uses a `ReentrantLock` or `synchronized` block per object. The Dart API calls the host through Pigeon, and the host objects carry the same locks, so concurrent Dart calls on one object are serialized on the host. The TypeScript API calls the host synchronously on the JavaScript thread, which is the only thread that reaches it.

The lock does not make a transport safe against lost or reordered messages. Noise nonces are a strict counter, so a lost message desynchronizes the two sides and the next decrypt fails.

## Errors

Every error belongs to one of six categories. The category is what an application branches on; the message is for logs. No message ever contains key material, plaintext, or ciphertext.

| Category | Meaning | C# exception type |
|---|---|---|
| **InvalidProtocolName** | The name is not `Noise_` plus four parts | `ArgumentException` |
| **UnsupportedFunction** | The pattern, modifier, DH, cipher, or hash is not supported | `NotSupportedException` |
| **InvalidArgument** | A length, count, or required argument is wrong; the object remains usable | `ArgumentException`, including `ArgumentOutOfRangeException` |
| **InvalidState** | Wrong turn, handshake complete or failed, one-way direction, nonce exhausted | `InvalidOperationException` |
| **AuthenticationFailed** | A message is truncated or its tag does not verify; during a handshake, terminal once a message pattern is consumed | `CryptographicException` and its subclasses |
| **Closed** | The object has been closed | `ObjectDisposedException` |

The Swift implementation defines `enum TorannError: Error` with one case per category, each carrying the message as its associated value except `closed`. The Kotlin implementation defines a sealed class `TorannException` with one subclass per category. The Dart implementation defines a sealed class `TorannException` with one subclass per category; the Pigeon host API carries the category as the error code and the message as the error message, and the Dart layer maps each code back to its subclass. The TypeScript implementation defines one class `TorannError` with a `code` property holding the category name in lower camel case (`invalidProtocolName`, `unsupportedFunction`, `invalidArgument`, `invalidState`, `authenticationFailed`, `closed`); the Expo host carries the category as the code of a coded exception, and the TypeScript layer copies it.

## Lifecycle and key hygiene

Every key pair, handshake state, and transport has an explicit `close()`. On close the library overwrites with zeros every key byte it owns: the key pair's private key; the handshake's static private key, ephemeral private key, PSKs, chaining key, and handshake cipher key; and the transport's two cipher keys. In C# this is `CryptographicOperations.ZeroMemory`. The platform cryptography libraries hold their own copies of keys that the library cannot reach: CryptoKit's `SymmetricKey` and `Curve25519.KeyAgreement.PrivateKey` in Swift, `javax.crypto.SecretKey` and Bouncy Castle arrays in Kotlin, and the copies the garbage collector makes in Kotlin. The Dart and TypeScript packages hold no keys of their own, but the platform channel buffers in Flutter and the Expo runtime buffers in React Native hold copies of every byte that crosses to the host. Each package README states these limits. The Swift implementation may also zero in `deinit`, the Dart implementation releases forgotten objects through a `Finalizer`, and the TypeScript implementation's host closes a forgotten object in `sharedObjectDidRelease` when the Expo runtime deallocates its JavaScript object, but none of these replaces `close()`.

Nothing ever falls back to plaintext. After `close()` every operation raises **Closed**, and the only cleartext the library produces is the handshake payload before a cipher key exists, which Noise defines.

## Protocol behavior shared by every implementation

The implementations share the following Noise behavior, which the vectors check:

- Patterns: the 38 patterns listed under "Patterns", with `psk` modifiers applied as described under "Parsing".
- SymmetricState initialization: `h` is the protocol name when it is at most the hash length, otherwise the hash of the name, and `ck` starts equal to `h` (Noise §5.2).
- HKDF: the Noise variant with two or three outputs and no info parameter (Noise §4.3). It is not RFC 5869 HKDF.
- `psk` handling: when the protocol has any `psk` modifier, every `e` token also calls `MixKey(e.public_key)` (Noise §9.2). A `psk` token calls `MixKeyAndHash(psk)`.
- Split: HKDF of the chaining key with empty input key material yields the two transport keys; the first goes to the initiator's send direction (Noise §5.2).
- Cipher nonces: 4 zero bytes then the 64-bit counter, little-endian for `ChaChaPoly` and big-endian for `AESGCM`.
- AEAD output: ciphertext followed by the 16-byte tag. CryptoKit returns them separately, and the Swift implementation concatenates them.
- Rekey: as defined under "Rekey".
- Random: ephemeral keys come from the platform's cryptographic random number generator unless a test has set a fixed ephemeral.
- BLAKE2 (C# and Kotlin): Noise uses the HMAC construction over BLAKE2 (Noise §4.3), not BLAKE2's keyed mode, with block sizes of 64 bytes for `BLAKE2s` and 128 bytes for `BLAKE2b`.

### Patterns

| Group | Patterns |
|---|---|
| One-way (Noise §7.4) | `N`, `K`, `X` |
| Fundamental (Noise §7.5) | `NN`, `NK`, `NX`, `KN`, `KK`, `KX`, `XN`, `XK`, `XX`, `IN`, `IK`, `IX` |
| Deferred (Noise §7.6) | `NK1`, `NX1`, `X1N`, `X1K`, `XK1`, `X1K1`, `X1X`, `XX1`, `X1X1`, `K1N`, `K1K`, `KK1`, `K1K1`, `K1X`, `KX1`, `K1X1`, `I1N`, `I1K`, `IK1`, `I1K1`, `I1X`, `IX1`, `I1X1` |

Each implementation carries the token tables for all 38 patterns, in `HandshakePattern.cs`, `HandshakePattern.swift`, and `HandshakePattern.kt`, and the vectors confirm every entry of each.

## Limits

| Quantity | Value |
|---|---|
| Maximum handshake or transport message | 65535 bytes |
| Authentication tag | 16 bytes |
| Maximum transport payload | 65519 bytes |
| PSK | 32 bytes |
| `25519` private key, public key, and DH output | 32 bytes |
| `448` private key, public key, and DH output (C# and Kotlin) | 56 bytes |
| Handshake hash | 32 bytes (`SHA256`, `BLAKE2s`), 64 bytes (`SHA512`, `BLAKE2b`) |
| Largest usable nonce | 2^64 − 2; 2^64 − 1 is reserved |

## Supported functions

| Function | C# | Swift | Kotlin | Dart and TypeScript |
|---|---|---|---|---|
| `25519` | Bouncy Castle `X25519` | CryptoKit `Curve25519.KeyAgreement` | Bouncy Castle `org.bouncycastle.math.ec.rfc7748.X25519` | via Swift and Kotlin |
| `448` | Bouncy Castle `X448` | not supported | Bouncy Castle `org.bouncycastle.math.ec.rfc7748.X448` | Android only |
| `ChaChaPoly` | .NET `ChaCha20Poly1305`, Bouncy Castle below Android API 28 | CryptoKit `ChaChaPoly` | JCA `ChaCha20-Poly1305` (`ChaCha20/Poly1305/NoPadding` on Android) | via Swift and Kotlin |
| `AESGCM` | .NET `AesGcm` | CryptoKit `AES.GCM` | JCA `AES/GCM/NoPadding` | via Swift and Kotlin |
| `SHA256`, `SHA512` | .NET `IncrementalHash` | CryptoKit `SHA256`, `SHA512`, `HMAC` | JCA `SHA-256`, `SHA-512`, `HmacSHA256`, `HmacSHA512` | via Swift and Kotlin |
| `BLAKE2s`, `BLAKE2b` | Bouncy Castle `Blake2sDigest`, `Blake2bDigest` under `HMac` | not supported | Bouncy Castle `Blake2sDigest`, `Blake2bDigest` under `HMac` | Android only |

C# and Kotlin support every function Torann defines, because the Bouncy Castle library that each already depends on for X25519 also contains `X448`, `Blake2sDigest`, and `Blake2bDigest`. Swift supports the subset only, because CryptoKit has neither X448 nor BLAKE2 and the Swift package takes no dependencies. The Dart and TypeScript APIs follow their host: a name with `448`, `BLAKE2s`, or `BLAKE2b` parses on Android and fails on iOS, so an application that runs on both platforms uses `25519` with `SHA256` or `SHA512`. A protocol name that asks for a function the platform does not support fails at parse time with **UnsupportedFunction**. The message names the function and is the same text on every platform. In Swift, and in Dart and TypeScript on iOS:

| Name | Error message |
|---|---|
| `Noise_XX_448_ChaChaPoly_SHA256` | `DH function '448' is not supported.` |
| `Noise_XX_25519_ChaChaPoly_BLAKE2s` | `Hash function 'BLAKE2s' is not supported.` |
| `Noise_XX_25519_ChaChaPoly_BLAKE2b` | `Hash function 'BLAKE2b' is not supported.` |
| `Noise_XX_448_ChaChaPoly_BLAKE2b` | `DH function '448' is not supported.` (the DH check runs first) |

In Swift the error is `TorannError.unsupportedFunction(message)`. In Dart it is `UnsupportedFunctionException` with that message, carried over Pigeon with the error code `unsupportedFunction`. In TypeScript it is a `TorannError` with the code `unsupportedFunction` and that message. The C# and Kotlin libraries raise their **UnsupportedFunction** errors (`NotSupportedException` and `TorannException.UnsupportedFunction`) only for names they do not recognize at all, such as `Noise_XX_25519_ChaChaPoly_SHA3`.

## Low-order public keys and all-zero DH output

Noise §12.1 says of X25519: "Invalid public key values will produce an output of all zeros. Alternatively, implementations are allowed to detect inputs that produce an all-zeros output and signal an error instead." Noise §14 names the attack: "a Noise_NK_25519 initiator might send an invalid ephemeral public key to cause a known DH output of all zeros."

Bouncy Castle offers `X25519.ScalarMult`, which performs no check, and `X25519.CalculateAgreement`, which returns false when the output is all zeros. The C# library and the Java class used by Kotlin both call `CalculateAgreement`.

On 2026-10-04 the following inputs were fed to CryptoKit and to Bouncy Castle 2.7.0 on macOS: `u = 0`, `u = 1`, the two order-8 points `e0eb7a7c…` and `5f9c95bc…`, `u = p − 1`, `u = p`, `u = p + 1`, and the non-low-order value with every bit set. The results:

| Implementation | Low-order inputs (7 values) | All-bits-set input |
|---|---|---|
| CryptoKit `sharedSecretFromKeyAgreement` | throws `CryptoKitError.underlyingCoreCryptoError(error: -7)` | returns a 32-byte secret |
| Bouncy Castle `X25519.ScalarMult` | returns 32 zero bytes, no error | returns a 32-byte secret |
| Bouncy Castle `X25519.CalculateAgreement` | returns `false` | returns `true` |

The Swift script that produced the CryptoKit row is reproduced here so the result can be rechecked:

```swift
import CryptoKit
let priv = Curve25519.KeyAgreement.PrivateKey()
let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(repeating: 0, count: 32))
_ = try priv.sharedSecretFromKeyAgreement(with: pub) // throws underlyingCoreCryptoError(error: -7)
```

CryptoKit gives the Swift implementation no way to continue with an all-zero output, so the Swift implementation must treat a low-order peer key as a failure. Every implementation does the same: a DH operation whose output would be all zeros raises **AuthenticationFailed** with the message `The peer's public key is invalid.`, and because every DH happens after a message pattern is consumed, the failure is terminal. The Kotlin implementation uses `X25519.calculateAgreement` and raises when it returns false, and `X448.calculateAgreement` in the same way for `448`. The Swift implementation maps the CryptoKit error to the same **AuthenticationFailed**. An honest peer never presents a low-order point, because the chance of generating one at random is negligible, so the check costs nothing in normal operation, and Noise §12.1 permits it.

The C# implementation calls `X25519.CalculateAgreement` and `X448.CalculateAgreement` and throws `CryptographicException` with the message above when either returns false.

## Test-only entry points

The vector tests need two things the public API does not expose, and the security tests need a third. None of them is reachable from the normal public API of any implementation.

1. **Fixed ephemeral key.** The vectors prescribe each party's ephemeral private key. In C#, `HandshakeState.FixedEphemeral` is an `internal` field, visible to the test project through `InternalsVisibleTo`. When it is set before the message that carries this party's `e` token is written, the handshake uses it instead of drawing a random key. In Swift it is the internal method `HandshakeState.setFixedEphemeral(_:)`, which takes the object's lock and checks the key length. The tests reach it with `@testable import Torann`, and the Flutter and React Native hosts call it directly, because they compile the Swift sources into their own module. In Kotlin it is the public method `HandshakeState.setFixedEphemeral(privateKey)` annotated with the opt-in marker `@TorannTestApi`, which is declared with `@RequiresOptIn(level = RequiresOptIn.Level.ERROR)`, because Kotlin `internal` is not visible from the `torann-testkit` module. Calling it without `@OptIn(TorannTestApi::class)` is a compile error. The method is also `@JvmSynthetic`, so a Java caller, whose compiler does not enforce the opt-in, cannot see it. In Dart it is the top-level function `setFixedEphemeral(handshake, privateKey)` exported only from `package:torann/testing.dart`, which `package:torann/torann.dart` does not export; it reaches the host through a Pigeon method that the normal Dart classes never call. In TypeScript it is the function `setFixedEphemeral(handshake, privateKey)` exported from `@stonygrey/torann/testing` and not from `@stonygrey/torann`; it calls a method of the native handshake object that the normal classes never call.
2. **Direct CipherState access.** `CryptoTests.RekeyMatchesTheSpecDefinition` builds a CipherState from a cipher name and a key, sets its nonce, calls rekey, and encrypts, and compares the result with the formula computed through the raw AEAD. Swift reaches `CipherState` and the cipher functions through `@testable import`. Kotlin exposes, under `@TorannTestApi`, a class `TestCipherState(cipherName, key)` with `setNonce`, `rekey`, and `encryptWithAd`, and a function `aeadEncrypt(cipherName, key, nonce, ad, plaintext)`; the constructor and every method are `@JvmSynthetic` for the same reason. Dart and TypeScript do not expose this; the Flutter and React Native example tests check rekey through the public `rekeySend` and `rekeyReceive` round trip instead, because the rekey derivation itself is tested in the Swift and Kotlin suites that the plugin compiles.
3. **Forced managed cipher.** `ChaChaPolyCipher.CreateKey(key, forceManaged: true)` in C# selects the Bouncy Castle fallback. It has no counterpart in the other implementations, which have no fallback.

## Naming

Names follow each language's conventions. Concepts, defaults, limits, and errors are identical.

| Concept | C# | Swift | Kotlin | Dart | TypeScript |
|---|---|---|---|---|---|
| Protocol type | `NoiseProtocol` | `NoiseProtocol` | `NoiseProtocol` | `NoiseProtocol` | `NoiseProtocol` |
| Parse | `NoiseProtocol.Parse(name)` | `NoiseProtocol.parse(_ name: String) throws` | `NoiseProtocol.parse(name: String)` | `static Future<NoiseProtocol> parse(String name)` | `static parse(name: string): NoiseProtocol` |
| Maximum message length | `NoiseProtocol.MaxMessageLength` | `NoiseProtocol.maxMessageLength` | `NoiseProtocol.MAX_MESSAGE_LENGTH` | `NoiseProtocol.maxMessageLength` | `NoiseProtocol.maxMessageLength` |
| Protocol name | `Name` | `name` | `name` | `name` | `name` |
| Generate key pair | `GenerateKeyPair()` | `generateKeyPair() throws -> KeyPair` | `generateKeyPair(): KeyPair` | `Future<KeyPair> generateKeyPair()` | `generateKeyPair(): KeyPair` |
| Key pair from private key | `CreateKeyPair(privateKey)` | `createKeyPair(privateKey: Data) throws -> KeyPair` | `createKeyPair(privateKey: ByteArray): KeyPair` | `Future<KeyPair> createKeyPair(Uint8List privateKey)` | `createKeyPair(privateKey: Uint8Array): KeyPair` |
| Create handshake | `CreateHandshake(initiator, prologue, s, remoteStatic, psks)` | `createHandshake(initiator:prologue:localStatic:remoteStatic:psks:) throws -> HandshakeState` | `createHandshake(initiator, prologue, localStatic, remoteStatic, psks): HandshakeState` | `Future<HandshakeState> createHandshake({required bool initiator, Uint8List? prologue, KeyPair? localStatic, Uint8List? remoteStatic, List<Uint8List>? psks})` | `createHandshake({ initiator, prologue?, localStatic?, remoteStatic?, psks? }): HandshakeState` |
| Key pair type | `KeyPair` | `KeyPair` | `KeyPair` | `KeyPair` | `KeyPair` |
| Private key | `PrivateKey` | `privateKey: Data { get throws }` | `val privateKey: ByteArray` | `Future<Uint8List> privateKey()` | `privateKey(): Uint8Array` |
| Public key | `PublicKey` | `publicKey: Data { get throws }` | `val publicKey: ByteArray` | `Uint8List get publicKey` | `get publicKey(): Uint8Array` |
| Handshake type | `HandshakeState` | `HandshakeState` | `HandshakeState` | `HandshakeState` | `HandshakeState` |
| Write handshake message | `WriteMessage(payload, buffer)` | `writeMessage(payload: Data = Data()) throws -> HandshakeWriteResult` | `writeMessage(payload: ByteArray = ByteArray(0)): HandshakeWriteResult` | `Future<HandshakeWriteResult> writeMessage([Uint8List? payload])` | `writeMessage(payload?: Uint8Array): HandshakeWriteResult` |
| Read handshake message | `ReadMessage(message, buffer)` | `readMessage(_ message: Data) throws -> HandshakeReadResult` | `readMessage(message: ByteArray): HandshakeReadResult` | `Future<HandshakeReadResult> readMessage(Uint8List message)` | `readMessage(message: Uint8Array): HandshakeReadResult` |
| Write result | `(int BytesWritten, byte[]? HandshakeHash, Transport? Transport)` | `HandshakeWriteResult { message, handshakeHash?, transport? }` | same | same | same |
| Read result | `(int BytesRead, byte[]? HandshakeHash, Transport? Transport)` | `HandshakeReadResult { payload, handshakeHash?, transport? }` | same | same | same |
| Remote static key | `RemoteStaticPublicKey` | `remoteStaticPublicKey: Data? { get throws }` | `val remoteStaticPublicKey: ByteArray?` | `Future<Uint8List?> remoteStaticPublicKey()` | `remoteStaticPublicKey(): Uint8Array | null` |
| Transport type | `Transport` | `Transport` | `Transport` | `Transport` | `Transport` |
| Tag size | `Transport.TagSize` | `Transport.tagSize` | `Transport.TAG_SIZE` | `Transport.tagSize` | `Transport.tagSize` |
| Write transport message | `WriteMessage(payload, buffer) -> int` | `writeMessage(payload: Data) throws -> Data` | `writeMessage(payload: ByteArray): ByteArray` | `Future<Uint8List> writeMessage(Uint8List payload)` | `writeMessage(payload: Uint8Array): Uint8Array` |
| Read transport message | `ReadMessage(message, buffer) -> int` | `readMessage(_ message: Data) throws -> Data` | `readMessage(message: ByteArray): ByteArray` | `Future<Uint8List> readMessage(Uint8List message)` | `readMessage(message: Uint8Array): Uint8Array` |
| Rekey | `RekeySend()`, `RekeyReceive()` | `rekeySend()`, `rekeyReceive()` | same | `Future<void>` versions | same |
| Set nonce | `SetSendNonce(ulong)`, `SetReceiveNonce(ulong)` | `setSendNonce(_ nonce: UInt64)`, `setReceiveNonce(_:)` | `setSendNonce(nonce: ULong)`, `setReceiveNonce(nonce: ULong)` | `Future<void> setSendNonce(int nonce)`, `setReceiveNonce(int nonce)` | `setSendNonce(nonce: number)`, `setReceiveNonce(nonce: number)` |
| Close | `Dispose()` | `close()` | `close()` (`AutoCloseable`) | `Future<void> close()` | `close()` |
| Errors | exception types in the "Errors" table | `TorannError` enum | `TorannException` sealed class | `TorannException` sealed class | `TorannError` class with `code` |
| Fixed ephemeral (test) | `FixedEphemeral` (internal) | `setFixedEphemeral(_:)` (internal, `@testable`) | `@TorannTestApi @JvmSynthetic setFixedEphemeral(privateKey)` | `setFixedEphemeral(handshake, privateKey)` in `testing.dart` | `setFixedEphemeral(handshake, privateKey)` in `@stonygrey/torann/testing` |

The type is `NoiseProtocol` in every language, because `Protocol` collides with Swift's `.Protocol` metatype syntax.

## Differences between the implementations

The implementations differ in the following ways, each on purpose.

1. **Returned arrays instead of caller-supplied buffers.** C# writes into a caller-supplied `Span<byte>` and returns a count. Swift, Kotlin, Dart, and TypeScript return a new array. Pigeon passes `Uint8List` values by copy and the Expo runtime passes `Uint8Array` values by copy, so a caller's buffer cannot be filled across the Dart or JavaScript boundary, and returned `Data` and `ByteArray` values are the platform idiom. The length limits are unchanged. The C# errors `The message buffer is too small for the ciphertext.`, `The payload buffer is too small for the plaintext.`, `The message buffer is too small for the handshake message.`, and `The payload buffer is too small for the handshake payload.` do not exist in Swift, Kotlin, Dart, and TypeScript.
2. **Result types instead of tuples.** `HandshakeWriteResult` and `HandshakeReadResult` replace the C# tuples.
3. **Asynchronous Dart API.** Every Dart method that reaches the host returns a `Future`, because every Pigeon call from Dart to the host is asynchronous. Dart `publicKey` is synchronous because the Dart object caches the public key when the key pair is created. The TypeScript API is synchronous throughout, because the Expo Modules API calls a native function on the JavaScript thread and returns its result directly.
4. **Dart nonce range.** Dart `int` is a signed 64-bit integer, so `setSendNonce` and `setReceiveNonce` in Dart accept 0 to 2^63 − 1 and raise **InvalidArgument** for a negative value. The reserved value 2^64 − 1 cannot be expressed from Dart, so that check is unreachable there.
5. **TypeScript nonce range.** A JavaScript `number` carries 53 bits of integer precision, so `setSendNonce` and `setReceiveNonce` in TypeScript accept 0 to 2^53 − 1 (`Number.MAX_SAFE_INTEGER`) and raise **InvalidArgument** for a negative, fractional, or larger value. The reserved value 2^64 − 1 cannot be expressed from JavaScript.
6. **Dart and TypeScript test APIs.** `package:torann/testing.dart` and `@stonygrey/torann/testing` expose the fixed ephemeral only, not CipherState, as described under "Test-only entry points".
7. **PSK argument type.** C# accepts any `IEnumerable<byte[]>`. Swift, Kotlin, Dart, and TypeScript take a list.
8. **Dart host failures.** The Dart API has a seventh exception, `HostFailureException`, for errors that are not Noise errors: the platform channel is gone (`channel-error`), the host threw something other than a Torann error (`hostFailure`, carrying only the exception type name), or a message was malformed. The six categories cannot express these, and mapping them to InvalidState would mislead an application. The TypeScript API uses the code `hostFailure` on `TorannError` for the same case, carrying only the host exception's type name.
9. **Closed key pair precedence in Dart and TypeScript.** Dart raises `ClosedException`, and TypeScript a `TorannError` with code `closed`, for a closed `localStatic` before calling the host, so it wins over the PSK checks that C#, Swift, and Kotlin run first. The spec fixes no order between `Closed` and the InvalidArgument checks.
10. **Swift function set.** Swift does not support `448`, `BLAKE2s`, or `BLAKE2b`, and neither do the Dart and TypeScript APIs on iOS. C#, Kotlin, and the Dart and TypeScript APIs on Android support them. The Bouncy Castle dependency of C# and Kotlin already contains the classes, and CryptoKit has none of them.
