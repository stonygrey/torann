<!-- Copyright © 2026 Stony Grey LLC. SPDX-License-Identifier: MIT -->

# Torann for React Native

Torann is the Noise Protocol Framework, revision 34, for React Native on iOS 18 and later and Android 13 (API 33) and later. The repository README at https://github.com/stonygrey/torann explains Noise and describes how the API is used. The package is an Expo module, which is the native module system that Expo provides for React Native, and it contains no cryptography of its own. On iOS it compiles the Swift implementation from this repository, from a copy under `ios/Torann` that `lib/sync-reactnative-sources` keeps identical to the original. On Android it depends on the Kotlin implementation, `com.stonygrey:torann`. Every method is synchronous, because the Expo Modules API calls a native function on the JavaScript thread without a round trip through a message bridge, and a handshake step completes in well under a millisecond.

## Functions

The functions the package supports are the functions its host supports: the Kotlin set on Android and the Swift set on iOS, as the table in the repository README lists them. `NoiseProtocol.parse` throws a `TorannError` with the code `unsupportedFunction` for a function the platform lacks.

## Installation

```sh
npm install @stonygrey/torann
```

The package needs the Expo Modules runtime. Every Expo app has it, and a bare React Native app adds it with `npx install-expo-modules@latest`. The application's iOS deployment target must be 18.0 or later and its Android `minSdk` 33 or later. An app that generates its native projects with `expo prebuild` sets both through the `expo-build-properties` plugin, as `example/app.json` does. On Android the package depends on `com.stonygrey:torann` from Maven Central.

## Usage

```ts
import { NoiseProtocol } from '@stonygrey/torann';

const protocol = NoiseProtocol.parse('Noise_XX_25519_ChaChaPoly_SHA256');
const staticKey = protocol.generateKeyPair();          // store staticKey.privateKey() for reuse
const handshake = protocol.createHandshake({ initiator: true, localStatic: staticKey });

const first = handshake.writeMessage();                // send first.message
// const reply = handshake.readMessage(received);
// ... the final message's result carries handshakeHash and transport
// const ciphertext = transport.writeMessage(payload);
// const plaintext = transport.readMessage(ciphertext);
```

Every byte sequence is a `Uint8Array`. Every error is a `TorannError` whose `code` is one of `invalidProtocolName`, `unsupportedFunction`, `invalidArgument`, `invalidState`, `authenticationFailed`, `closed`, or `hostFailure`. The last is for a failure that is not a Noise error, and its message carries the native exception's type name and nothing else.

Call `close()` on every `KeyPair`, `HandshakeState`, and `Transport`. After `close()` every method throws `closed` without reaching the native side. Each JavaScript object is an Expo shared object, which is an object whose native half the Expo runtime keeps alive as long as the JavaScript half exists. The native half is the Swift or Kotlin object, and the host closes it in `sharedObjectDidRelease`, which the Expo runtime calls when the JavaScript object is deallocated. That release is the backstop for a forgotten `close()`, not a replacement for it, because the time of deallocation is not defined.

## Crypto

The package holds no keys in JavaScript. The limits of the Swift and Kotlin implementations apply unchanged and are described in `swift/README.md` and `kotlin/torann/README.md`.

The JavaScript boundary adds one more place where bytes live. Every `Uint8Array` passed to the native side is copied by the Expo runtime into a `Data` on iOS or a `ByteArray` on Android, and every returned array is copied into a new JavaScript `ArrayBuffer`. Neither side can zero the other's copy, and JavaScript cannot zero its own reliably. Private keys cross that boundary only when the application calls `privateKey()` or `createKeyPair`, and pre-shared keys cross it on `createHandshake`. Public keys, handshake messages, payloads, and ciphertexts cross it on every call. The Android host zeros the decoded arrays that carried a private key, a pre-shared key, or a test ephemeral key as soon as the library has copied them, which removes one of the JVM copies but not the ones the runtime and the garbage collector hold.

`setSendNonce` and `setReceiveNonce` take a JavaScript `number`, which holds 53 bits of integer precision, so the range is 0 to `Number.MAX_SAFE_INTEGER`, and anything else throws `invalidArgument`. The reserved nonce 2^64 − 1 cannot be expressed from JavaScript.

## Tests

`npm test` runs the Jest unit tests of the JavaScript layer against a fake native module. They cover error mapping, the tracking of closed objects, nonce validation, and the passing of results. The example app is the device test. `cd example && npx expo prebuild && npx expo run:ios`, or `run:android`, builds it and runs the shared vectors through the package, 440 vectors on iOS and 1,352 on Android, then handshakes with random keys through the public API, the RFC 7748 §6 key derivation examples, and the platform's function set, and prints one `TORANN` line per suite to the Metro terminal. Metro is the bundler that serves the JavaScript to the app while it runs. The example resolves `com.stonygrey:torann` from `mavenLocal()` until the artifact is on Maven Central: `cd kotlin && ./gradlew :torann:publishToMavenLocal` puts it there, and the config plugin `example/plugins/withMavenLocal.js` adds that repository to the Gradle project that `expo prebuild` generates.

The test-only entry point that sets a fixed ephemeral key is exported from `@stonygrey/torann/testing` and not from `@stonygrey/torann`. JavaScript has no privilege boundary inside a process, so the native function behind it exists in every build.
