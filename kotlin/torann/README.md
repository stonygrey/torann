<!-- Copyright © 2026 Stony Grey LLC. SPDX-License-Identifier: MIT -->

# Torann for Kotlin

Torann is a Kotlin implementation of the Noise Protocol Framework, revision 34, for Android 13 (API 33) and later and for the JVM, compiled to Java 11 bytecode. The repository README at https://github.com/stonygrey/torann explains Noise and describes how the API is used, and `readme/torann-api.md` specifies the API that every Torann package shares. The Gradle build is in `kotlin/`. The library is the `kotlin/torann` module, the shared tests are in `kotlin/torann-testkit`, and `kotlin/android-tests` runs those tests as Android instrumented tests. The Maven coordinates are `com.stonygrey:torann`.

## Functions

The Diffie-Hellman functions are `25519` and `448`, the ciphers are `ChaChaPoly` and `AESGCM`, and the hashes are `SHA256`, `SHA512`, `BLAKE2s`, and `BLAKE2b`. That is every function Torann defines, and the test kit runs all 1,352 shared vectors with none skipped, on the JVM and on Android emulators.

## Installation

```kotlin
implementation("com.stonygrey:torann:0.3.1")
```

The artifact is published to Maven Central through the Central Portal by `.github/workflows/release.yml`. During development, `./gradlew :torann:publishToMavenLocal` puts the same artifact in `~/.m2`, and that is where the Flutter and React Native example apps resolve it.

The jar is compiled by Kotlin 2.4.20 but carries Kotlin 2.1 metadata and depends on `kotlin-stdlib` 2.1.20. The settings that do this are `languageVersion`, `apiVersion`, and `coreLibrariesVersion` in `torann/build.gradle.kts`. The reason is that a Kotlin compiler reads metadata at most one minor version newer than itself, and React Native 0.86 compiles its Android projects with Kotlin 2.1.20. A consumer on Kotlin 2.1 or later can therefore use the jar.

## Usage

```kotlin
import com.stonygrey.torann.NoiseProtocol

val protocol = NoiseProtocol.parse("Noise_XX_25519_ChaChaPoly_SHA256")
val staticKey = protocol.generateKeyPair()                 // store staticKey.privateKey for reuse
val handshake = protocol.createHandshake(initiator = true, localStatic = staticKey)

val first = handshake.writeMessage()                       // send first.message
// val reply = handshake.readMessage(received)
// ... the final message's result carries handshakeHash and transport
// val ciphertext = transport.writeMessage(payload)
// val plaintext = transport.readMessage(ciphertext)
```

Errors are the subclasses of the sealed class `TorannException`, one per category. `KeyPair`, `HandshakeState`, and `Transport` implement `AutoCloseable`, and every operation runs under a lock inside the object. After `close()` every operation throws `TorannException.Closed`.

## Crypto

The AEAD ciphers and the SHA-2 hashes come from the Java Cryptography Architecture, the JCA, which is the standard Java interface to cryptographic providers. The algorithm names used are `AES/GCM/NoPadding`, `ChaCha20-Poly1305`, `SHA-256`, `SHA-512`, `HmacSHA256`, and `HmacSHA512`. Android's Conscrypt provider names the ChaCha20-Poly1305 cipher `ChaCha20/Poly1305/NoPadding`, and the library tries both names once. On Android these algorithms are Conscrypt's BoringSSL implementations; on the JDK they are SunJCE's. X25519, X448, BLAKE2s, and BLAKE2b come from Bouncy Castle (`org.bouncycastle:bcprov-jdk18on`), through `org.bouncycastle.math.ec.rfc7748.X25519` and `X448`, and through `Blake2sDigest` and `Blake2bDigest` under Bouncy Castle's `HMac`. Android's platform provider has no X448 and no BLAKE2, because BoringSSL implements neither.

A new `Cipher` instance is created for every encryption and decryption. The JDK's providers refuse to initialize one instance for encryption twice with the same key and nonce, and the nonce-setter API and its tests do exactly that on purpose.

The library calls Bouncy Castle's `calculateAgreement`, which returns false for a low-order peer key, and then raises `TorannException.AuthenticationFailed("The peer's public key is invalid.")`.

Key hygiene is limited by the JVM. The library zeros every key array it owns with `java.util.Arrays.fill`, but it cannot reach the copies the providers make. `javax.crypto.spec.SecretKeySpec` copies the key in its constructor and its `destroy()` is not implemented, and Bouncy Castle's `KeyParameter` clones the key it is given. The garbage collector may move or copy any array before the library zeros it, and the library makes no attempt to scrub those copies.

Private keys are generated as raw random bytes from a shared `java.security.SecureRandom` instance, and Bouncy Castle clamps the scalar inside the operation. A private key supplied through `createKeyPair` is used as given.

## Tests

`./gradlew :torann:test` runs the vectors, the security tests, and the RFC 7748 §6.1 and §6.2 key derivation examples on the JVM. `./gradlew :android-tests:connectedCheck` runs the same test kit as instrumented tests on a connected emulator, with the vector files packaged as assets of the test APK. The test-only entry point that sets a fixed ephemeral key is `HandshakeState.setFixedEphemeral`, which requires `@OptIn(TorannTestApi::class)` and is hidden from Java callers with `@JvmSynthetic`.
