<!-- Copyright © 2026 Stony Grey LLC. SPDX-License-Identifier: MIT -->

# Test vectors

This folder holds the two Noise Protocol Framework test vector files that every Torann implementation runs. A test vector is a complete recorded session in which every key is fixed, so that an implementation can be compared byte for byte with the implementation that produced the recording. Both files are copies of the upstream files, byte for byte. They keep the upstream `.txt` extension even though their content is JSON, so that a hash of either file matches a hash of the upstream file. Nothing in this folder is edited after it is copied. The C# test project links to these files rather than keeping its own copies. If an implementation fails a vector, the implementation is wrong.

## Source and license

`cacophony.txt` is the file `vectors/cacophony.txt` from the cacophony project (https://github.com/haskell-cryptography/cacophony), a Haskell implementation of Noise. The copy here is byte-identical to that file on the `master` branch as checked on 2026-10-04. The last upstream commit that changed the file is `18b7348c54fd61fcd0c220298883de0d09c8364d`, dated 2018-12-16 and titled "Add deferred pattern support". Cacophony's `LICENSE` file releases the project into the public domain under the Unlicense.

`snow.txt` is the file `tests/vectors/snow.txt` from the snow project (https://github.com/mcginty/snow), a Rust implementation of Noise, at commit `8ac60f51cfe3`. The copy here is byte-identical to the file at that commit. Both comparisons used SHA-256. Snow is dual-licensed under MIT and Apache-2.0, and either license may be chosen for the copy here.

## File format

Each file is a JSON object with one key, `vectors`, whose value is an array of vector objects. Every byte string is lower-case hex. A vector has the following fields.

- `protocol_name` is the full Noise protocol name, in the form `Noise_<pattern><modifiers>_<dh>_<cipher>_<hash>`, for example `Noise_XXpsk3_25519_ChaChaPoly_SHA256`. A runner passes this string to the protocol parser, which is `NoiseProtocol.Parse` in C#.
- `init_prologue` and `resp_prologue` are the prologue each side passes when it creates its handshake. The prologue is data both parties must agree on; it is mixed into the handshake hash and never transmitted. The two values are identical in every vector of both files. A runner passes `init_prologue` to the initiator and `resp_prologue` to the responder.
- `init_static` and `resp_static` are the private static key of that side. The field is present only when the pattern gives that side a static key. A runner derives the public key from the private key, with `NoiseProtocol.CreateKeyPair` in C#.
- `init_remote_static` and `resp_remote_static` are the public static key of the peer, supplied before the handshake starts. The field is present only when the pattern has a pre-message token for that key, which means the key is known to the other side before the first message.
- `init_ephemeral` and `resp_ephemeral` are the private ephemeral key that side must use instead of a random one. Setting it needs an entry point the public API does not expose, which in C# is the `internal` field `HandshakeState.FixedEphemeral`. Cacophony omits `resp_ephemeral` for the one-way patterns `N`, `K`, and `X`, where the responder sends nothing. Snow carries `resp_ephemeral` in every vector, including the one-way patterns, where the handshake never reads it.
- `init_psks` and `resp_psks` are arrays of 32-byte pre-shared keys, identical to each other in every vector. Cacophony includes the fields only in vectors whose pattern has a `psk` modifier, and each of those vectors carries exactly one key. Snow includes them in every vector, with an empty array when there is no `psk` modifier. Snow's `psk` vectors combine modifiers, for example `NXpsk0+psk1+psk2`, so each carries two, three, or four keys and none carries one. A runner passes the array in order, and the handshake consumes one key at each `psk` token in the order the tokens occur in the pattern.
- `handshake_hash` is the handshake hash both sides must hold when the handshake completes. The handshake hash is a running hash of everything the two sides have exchanged, so agreement on it means agreement on the whole transcript. Cacophony includes it in every vector, and its length is the hash output length, which is 32 bytes for `SHA256` and `BLAKE2s` and 64 bytes for `SHA512` and `BLAKE2b`. Snow does not include it in any vector, so a runner compares the two sides' hashes against each other when the field is absent.
- `messages` is an array of objects, each with a `payload` and the `ciphertext` that payload must produce. Messages alternate direction starting with the initiator, except in the one-way patterns, where every message goes from initiator to responder. The first messages are handshake messages, and any that remain after the handshake completes are transport messages. For each message the runner has the sending side write `payload` and compares the output with `ciphertext`, then has the receiving side read `ciphertext` and compares the output with `payload`. Cacophony has 6 messages in every vector. Snow has between 2 and 6.

No vector in either file marks an expected failure. Every vector is expected to pass, and a runner fails when any comparison differs. Neither file contains vectors for the `fallback` modifier, and neither contains the X25519 examples of RFC 7748.

## Counts

| | `cacophony.txt` | `snow.txt` |
|---|---|---|
| Vectors | 944 | 408 |
| DH `25519` | 472 | 408 |
| DH `448` | 472 | 0 |
| Cipher `ChaChaPoly` | 472 | 204 |
| Cipher `AESGCM` | 472 | 204 |
| Hash `SHA256` | 236 | 102 |
| Hash `SHA512` | 236 | 102 |
| Hash `BLAKE2s` | 236 | 102 |
| Hash `BLAKE2b` | 236 | 102 |
| Vectors with a `psk` modifier | 336 | 104 |

Cacophony covers all 38 patterns the Noise specification defines, which is 3 one-way, 12 fundamental, and 23 deferred patterns, each across the 16 combinations of Diffie-Hellman function, cipher, and hash. Snow uses `25519` only.

The C# implementation supports every function in both files, and `ReferenceVectorTests` asserts that at least 944 and 408 vectors ran. The Kotlin implementation, and the Flutter plugin and the React Native package on Android, support every function in both files as well, and their runners assert that 944 and 408 vectors ran with none skipped. The Swift implementation, and the Flutter plugin and the React Native package on iOS, support `25519`, `ChaChaPoly`, `AESGCM`, `SHA256`, and `SHA512` only. Their runners skip every vector whose name contains `448`, `BLAKE2s`, or `BLAKE2b`, and assert that 440 ran:

| | `cacophony.txt` | `snow.txt` |
|---|---|---|
| `25519` `ChaChaPoly` `SHA256` | 59 | 51 |
| `25519` `ChaChaPoly` `SHA512` | 59 | 51 |
| `25519` `AESGCM` `SHA256` | 59 | 51 |
| `25519` `AESGCM` `SHA512` | 59 | 51 |
| Supported total | 236 | 204 |

## How the C# tests read the files

`dotnet/tests/Torann.Tests/Torann.Tests.csproj` includes `..\..\..\vectors\*.txt` with `Link="Vectors\%(Filename)%(Extension)"` and `CopyToOutputDirectory="PreserveNewest"`, so the build copies both files to a `Vectors` folder next to the test assembly. `ReferenceVectorTests` reads them from `AppContext.BaseDirectory/Vectors`. The link keeps that runtime path the same as it was when the files lived inside the test project, so the test code did not change when the files moved here.
