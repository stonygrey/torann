<!-- Copyright © 2026 Stony Grey LLC. SPDX-License-Identifier: MIT -->

# Running the shared vectors

## Purpose

This document describes how a vector runner maps the two files in `vectors/` onto the API in `readme/torann-api.md`, which vectors the Swift, Kotlin, Dart, and TypeScript runners skip, and the counts each runner must report. The provenance, license, and field inventory of the files are in `vectors/README.md`. The C# runner is `dotnet/tests/Torann.Tests/ReferenceVectorTests.cs`, and the runners in the other languages follow the same steps.

## What a vector is

Each file is a JSON object with one key, `vectors`, an array of vector objects. A vector describes one complete session between an initiator and a responder with every key fixed: the protocol name, each party's inputs, and the exact bytes of every message. Because every input is fixed, a vector checks the implementation's byte-for-byte agreement with the reference suites. It does not test key generation, which `interop/run.py` covers with keys that each implementation generates itself.

## Field to API mapping

Every byte string in a vector is lower-case hex and is decoded to bytes before use.

| Field | Where it goes |
|---|---|
| `protocol_name` | `NoiseProtocol.parse` |
| `init_prologue`, `resp_prologue` | the `prologue` argument of `createHandshake` for the initiator and the responder |
| `init_static`, `resp_static` | `createKeyPair(privateKey)`, then the `localStatic` argument of the respective `createHandshake`. Absent means no local static key. |
| `init_remote_static`, `resp_remote_static` | the `remoteStatic` argument of the respective `createHandshake`. Absent means none. |
| `init_psks`, `resp_psks` | the `psks` argument of the respective `createHandshake`. Absent means an empty list. |
| `init_ephemeral`, `resp_ephemeral` | the test-only fixed ephemeral of the respective handshake, set after `createHandshake` and before the first message. Absent means not set. |
| `handshake_hash` | compared with the `handshakeHash` of both parties' final handshake results when present |
| `messages[i].payload` | the `payload` argument of `writeMessage` for message `i`, and the expected `payload` of the reader's result |
| `messages[i].ciphertext` | the expected `message` of the writer's result, and the `message` argument of `readMessage` for message `i` |

Snow carries `resp_ephemeral` for one-way patterns, where the responder never writes an `e` token. The runner sets it anyway, and the handshake never reads it.

## Steps for one vector

1. Parse `protocol_name`. If parsing raises **UnsupportedFunction**, count the vector as skipped and continue with the next vector. Any other error fails the run.
2. Create the initiator's key pair from `init_static` and the responder's from `resp_static`, when present.
3. Create the initiator handshake with `initiator = true`, `init_prologue`, the initiator key pair, `init_remote_static`, and `init_psks`. Create the responder handshake with `initiator = false` and the `resp_` fields.
4. Set the fixed ephemeral of each handshake from `init_ephemeral` and `resp_ephemeral`.
5. For each element of `messages`, in order:
   - Decide who writes. Until the handshake completes, message `i` is written by the initiator when `i` is even and by the responder when `i` is odd. Once a transport exists, the same alternation continues, except that a one-way pattern's messages are all written by the initiator. The runner knows the pattern is one-way when the write result of message 0 already carries a transport, because an interactive pattern has at least two messages.
   - While no transport exists: the writer calls `writeMessage(payload)`; the result's `message` must equal `ciphertext`. The reader calls `readMessage(ciphertext)`; the result's `payload` must equal `payload`. If the writer's result carries a transport, the reader's result must carry one too. Keep the initiator's and the responder's transports. If `handshake_hash` is present, both results' `handshakeHash` must equal it. If it is absent, the two `handshakeHash` values must equal each other.
   - Once transports exist: the writer's transport calls `writeMessage(payload)`, and the output must equal `ciphertext`. The reader's transport calls `readMessage(ciphertext)`, and the output must equal `payload`.
6. Close both transports and both handshakes.

A comparison that differs fails the vector. The runner reports the failing vector's `protocol_name` and the index of the message, and the whole suite fails. The C# runner does this with `Assert.Fail($"Vector '{vector.ProtocolName}' failed: {e}")`.

## Skip rule and counts

The Swift implementation, and the Dart and TypeScript APIs on iOS, support `25519`, `ChaChaPoly`, `AESGCM`, `SHA256`, and `SHA512` only. Their parsers raise **UnsupportedFunction** for every name containing `448`, `BLAKE2s`, or `BLAKE2b`, and the runner skips those vectors by catching that error in step 1. The Kotlin implementation, and the Dart and TypeScript APIs on Android, support every function in both files and skip nothing. The runner does not filter by inspecting the name itself, so a parser that wrongly accepts an unsupported function shows up as a vector failure rather than a silent skip.

Each runner prints how many vectors it ran and how many it skipped, per file, in the form the C# runner uses: `cacophony.txt: ran 236 vectors, skipped 708 unsupported.` It then asserts the exact counts:

| File | Total | Swift, Dart, and TypeScript on iOS: run | skipped | Kotlin, Dart, and TypeScript on Android: run | skipped |
|---|---|---|---|---|---|
| `cacophony.txt` | 944 | 236 | 708 | 944 | 0 |
| `snow.txt` | 408 | 204 | 204 | 408 | 0 |
| Both | 1352 | 440 | 912 | 1352 | 0 |

The Swift, Kotlin, Dart, and TypeScript runners assert the run and skipped counts as exact values, not minimums, so a parser that starts accepting or rejecting the wrong names fails the test in both directions. The C# runner asserts minimums of 944 and 408, which amounts to the same check because the files hold no more vectors than that.

The 440 vectors that Swift runs are spread evenly over the four cipher and hash combinations: 59 per combination in cacophony and 51 per combination in snow.

## Locating the files

The files stay in `vectors/` and are never copied into a source tree by hand. The C# test project links them into its output directory through the project file. The Swift test target locates `vectors/` from `#filePath`, which works under both `swift test` and `xcodebuild test`, because the Simulator runs the test process on the host and reads the host file system. The Kotlin testkit reads `../vectors` on the JVM and packages the files as `androidTest` assets for the emulator. The Flutter example app receives copies made by `lib/sync-flutter-sources`, whose `--check` mode fails when a copy differs from `vectors/`. The React Native example app receives copies made by `lib/sync-reactnative-sources` under the names `cacophony.json` and `snow.json`, because Metro bundles a `.json` file through `require()` and has no loader for `.txt`; the content is byte for byte the same, and the script's `--check` mode compares it the same way. That runner prints `cacophony.json: ran 236 vectors, skipped 708 unsupported.` with the `.json` name.
