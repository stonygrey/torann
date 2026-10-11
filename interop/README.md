<!-- Copyright © 2026 Stony Grey LLC. SPDX-License-Identifier: MIT -->

# Cross-implementation interop test

`interop/run.py` completes live Noise handshakes between every ordered pair of the C#, Swift, and Kotlin implementations, using keys that each implementation generates itself. The shared test vectors fix every key, so they never exercise key generation or the byte encoding of a generated key. This test does. It runs the patterns `NN`, `NK`, `KK`, `IK`, `XX`, `XXpsk3`, and the one-way pattern `X`. A pair that involves Swift runs the four suites Swift supports, which are `25519` with `ChaChaPoly` or `AESGCM` and with `SHA256` or `SHA512`. The four pairs that do not involve Swift run all 16 combinations of Diffie-Hellman function, cipher, and hash. That is 5 × 7 × 4 + 4 × 7 × 16 = 588 runs.

For each run the runner checks that both sides report the same handshake hash, that each side's learned remote static key equals the peer's generated public key, that transport messages decrypt in both directions, that rekey works in each direction, that a tampered transport message is rejected and leaves the transport usable, and, for `X`, that the reverse direction raises the one-way error.

## Drivers

A driver is a small program, one per implementation, that reads commands from standard input one line at a time and writes one response line to standard output per command. The runner keeps one driver process per implementation alive for the whole pair and starts a new session with each `init` command.

| Implementation | Source | Built by | Launched as |
|---|---|---|---|
| C# | `dotnet/interop/Torann.Interop/` | `dotnet build dotnet/interop/Torann.Interop -c Release` | `dotnet dotnet/interop/Torann.Interop/bin/Release/net9.0/Torann.Interop.dll` |
| Swift | `swift/Sources/TorannInterop/`, an executable target in `Package.swift` | `swift build -c release --target TorannInterop` | `.build/release/TorannInterop` |
| Kotlin | `kotlin/interop-driver/` | `cd kotlin && ./gradlew :interop-driver:installDist` | `kotlin/interop-driver/build/install/interop-driver/bin/interop-driver` |

`run.py` runs the three build commands first. The Kotlin build and driver need `JAVA_HOME` to point at a JDK 17 or later.

## Protocol

Every byte string is lower-case hex. An empty byte string is written as `-`. Fields are separated by single spaces. Every response starts with `ok` or `error`.

| Command | Response | Meaning |
|---|---|---|
| `keygen <protocol>` | `ok <private> <public>` | Generates a static key pair with the implementation's own key generation. |
| `init <protocol> <initiator\|responder> <prologue> <local-static-private> <remote-static-public> <psks>` | `ok` | Starts a session, closing any previous one. `<psks>` is a comma-separated list of 32-byte keys, or `-`. The local static key is given as its private key, and the driver rebuilds the key pair. |
| `write <payload>` | `ok <message>` or `ok <message> done <handshake-hash>` | Writes the next handshake message, or a transport message once the handshake is complete. `done` marks the final handshake message. |
| `read <message>` | `ok <payload>` or `ok <payload> done <handshake-hash>` | Reads a handshake or transport message. |
| `rekey send` / `rekey receive` | `ok` | Rekeys one direction of the transport. |
| `hash` | `ok <handshake-hash>` | The handshake hash of the completed handshake. |
| `remote-static` | `ok <public>` or `ok -` | The handshake's `remoteStaticPublicKey`, or `-` when none is known. |
| `quit` | `ok` | Exits the driver. |

A failed command answers `error <category> <message>`, where `<category>` is one of the six error categories every implementation uses: `invalidProtocolName`, `unsupportedFunction`, `invalidArgument`, `invalidState`, `authenticationFailed`, or `closed`. The session stays in whatever state the implementation left it. After a terminal handshake failure the next `write` or `read` answers `error invalidState ...`.

## Running

```
JAVA_HOME="/path/to/jdk" python3 interop/run.py
```

The runner prints one line per pair and a final total, and exits with status 1 if any run fails. `--pairs csharp:swift` restricts the pairs, and `--skip-build` reuses the existing driver binaries.
