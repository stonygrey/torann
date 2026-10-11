<!-- Copyright © 2026 Stony Grey LLC. SPDX-License-Identifier: MIT -->

# Torann for Flutter

Torann is the Noise Protocol Framework, revision 34, for Flutter on iOS 18 and later and Android 13 (API 33) and later. The repository README at https://github.com/stonygrey/torann explains Noise and describes how the API is used. The plugin contains no cryptography of its own. On iOS it compiles the Swift implementation from this repository, from a copy under `ios/torann/Sources/torann/Torann` that `lib/sync-flutter-sources` keeps identical to the original. On Android it depends on the Kotlin implementation, `com.stonygrey:torann`. The Dart code talks to that native code through Pigeon, Flutter's generator for typed platform channels, and every Pigeon call is asynchronous, so every method that reaches the native side returns a `Future`.

## Functions

The functions the plugin supports are the functions its host supports: the Kotlin set on Android and the Swift set on iOS, as the table in the repository README lists them. `NoiseProtocol.parse` throws `UnsupportedFunctionException` for a function the platform lacks.

## Installation

```yaml
dependencies:
  torann: ^0.3.1
```

The application's iOS deployment target must be 18.0 or later and its Android `minSdk` 33 or later. On Android the plugin depends on `com.stonygrey:torann` from Maven Central.

## Usage

```dart
import 'package:torann/torann.dart';

final protocol = await NoiseProtocol.parse('Noise_XX_25519_ChaChaPoly_SHA256');
final staticKey = await protocol.generateKeyPair();     // store await staticKey.privateKey() for reuse
final handshake = await protocol.createHandshake(initiator: true, localStatic: staticKey);

final first = await handshake.writeMessage();           // send first.message
// final reply = await handshake.readMessage(received);
// ... the final message's result carries handshakeHash and transport
// final ciphertext = await transport.writeMessage(payload);
// final plaintext = await transport.readMessage(ciphertext);
```

Errors are the subclasses of the sealed class `TorannException`, one per category, plus `HostFailureException` for a failure that is not a Noise error, such as a platform channel that is gone or a native exception of another kind; its message carries the native exception's type name and nothing else.

Call `close()` on every `KeyPair`, `HandshakeState`, and `Transport`. After `close()` every method throws `ClosedException` without reaching the native side. A `Finalizer`, which is Dart's hook for running code when an object is garbage collected, releases the native object of anything the application forgot to close. In debug builds the finalizer prints one line naming the object's type and handle, and that line is the only output the package produces.

## Crypto

The plugin holds no keys in Dart. Each Dart object holds an integer handle, which is an index into a table on the native side, and that table entry refers to an object that the Swift or Kotlin library owns. The native side removes the entry and closes the object when Dart calls `close()`. The limits of the Swift and Kotlin implementations apply unchanged and are described in `swift/README.md` and `kotlin/torann/README.md`.

The Dart boundary adds one more place where bytes live. Every `Uint8List` passed to or returned from the native side crosses the platform channel through Pigeon's standard message codec, which copies it into channel buffers that Dart cannot zero. Private keys cross that boundary only when the application calls `privateKey()` or `createKeyPair`, and pre-shared keys cross it on `createHandshake`. Public keys, handshake messages, payloads, and ciphertexts cross it on every call. The Android host zeros the decoded arrays that carried a private key or a pre-shared key as soon as the library has copied them, which removes one of the JVM copies but not the ones the platform channel and the garbage collector hold. When a Flutter engine detaches, both hosts close every object still open, so handshake and transport keys are wiped at that point rather than left to the garbage collector.

`setSendNonce` and `setReceiveNonce` take a Dart `int`, which is a signed 64-bit integer, so the range is 0 to 2^63 − 1, and a negative value throws `InvalidArgumentException`.

## Tests

`flutter test` runs the Dart unit tests against a fake native side. `cd example && flutter test integration_test -d <device>` runs the shared vectors through the plugin on a device or simulator, 440 vectors on iOS and 1,352 on Android, and runs handshakes with random keys through the public API. The test-only entry point that sets a fixed ephemeral key is exported from `package:torann/testing.dart`, which `package:torann/torann.dart` does not export. Dart has no privilege boundary inside a process, so the native method behind it exists on the platform channel in every build.
