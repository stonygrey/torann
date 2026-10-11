#!/usr/bin/env python3
# Copyright © 2026 Stony Grey LLC.
# SPDX-License-Identifier: MIT
"""Runs live handshakes between every ordered pair of Torann implementations.

See interop/README.md for the driver protocol and the checks performed here.
"""

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DRIVERS = {
    "csharp": {
        "build": ["dotnet", "build", "dotnet/interop/Torann.Interop", "-c", "Release", "--nologo", "-v", "q"],
        "run": ["dotnet", "dotnet/interop/Torann.Interop/bin/Release/net9.0/Torann.Interop.dll"],
        "full": True,
    },
    "swift": {
        # --product, not --target: SwiftPM in Xcode 16 compiles a target named with
        # --target without linking its executable, and the build then reports success.
        "build": ["swift", "build", "-c", "release", "--product", "TorannInterop"],
        "run": [".build/release/TorannInterop"],
        "full": False,
    },
    "kotlin": {
        "build": ["kotlin/gradlew", "-p", "kotlin", ":interop-driver:installDist", "-q"],
        "run": ["kotlin/interop-driver/build/install/interop-driver/bin/interop-driver"],
        "full": True,
    },
}

PATTERNS = ["NN", "NK", "KK", "IK", "XX", "XXpsk3", "X"]
DHS_FULL = ["25519", "448"]
CIPHERS = ["ChaChaPoly", "AESGCM"]
HASHES_FULL = ["SHA256", "SHA512", "BLAKE2s", "BLAKE2b"]
HASHES_SWIFT = ["SHA256", "SHA512"]

# Which static keys each pattern needs and who knows whose key up front.
# (initiator has static, responder has static, initiator knows rs, responder knows rs)
PATTERN_KEYS = {
    "NN": (False, False, False, False),
    "NK": (False, True, True, False),
    "KK": (True, True, True, True),
    "IK": (True, True, True, False),
    "XX": (True, True, False, False),
    "XXpsk3": (True, True, False, False),
    "X": (True, True, True, False),
}
ONE_WAY = {"X"}
MESSAGE_COUNT = {"NN": 2, "NK": 2, "KK": 2, "IK": 2, "XX": 3, "XXpsk3": 3, "X": 1}


class Failure(Exception):
    pass


class Driver:
    def __init__(self, name):
        self.name = name
        # Every command is relative to the repository root; Popen resolves the executable
        # against cwd on POSIX, so the drivers run from any working directory.
        self.proc = subprocess.Popen(DRIVERS[name]["run"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1, cwd=ROOT)

    def send(self, line):
        self.proc.stdin.write(line + "\n")
        self.proc.stdin.flush()
        response = self.proc.stdout.readline()
        if response == "":
            err = self.proc.stderr.read()
            raise Failure(f"{self.name} driver exited; stderr: {err[-2000:]}")
        return response.rstrip("\n").split(" ")

    def ok(self, line):
        parts = self.send(line)
        if parts[0] != "ok":
            raise Failure(f"{self.name}: '{line[:60]}' -> {' '.join(parts)}")
        return parts[1:]

    def expect_error(self, line, category):
        parts = self.send(line)
        if parts[0] != "error" or parts[1] != category:
            raise Failure(f"{self.name}: expected 'error {category}' for '{line[:60]}', got {' '.join(parts)[:200]}")
        return " ".join(parts[2:])

    def close(self):
        try:
            self.send("quit")
        except Exception:
            pass
        self.proc.kill()
        self.proc.wait()


def hexify(data):
    return data.hex() if data else "-"


def run_session(init, resp, protocol, pattern):
    """Runs one protocol between an initiator driver and a responder driver."""
    i_static, r_static, i_knows, r_knows = PATTERN_KEYS[pattern]
    i_keys = init.ok(f"keygen {protocol}") if i_static else None
    r_keys = resp.ok(f"keygen {protocol}") if r_static else None
    psk = os.urandom(32).hex() if "psk" in pattern else "-"
    prologue = hexify(os.urandom(16))

    init.ok(f"init {protocol} initiator {prologue} {i_keys[0] if i_keys else '-'} {r_keys[1] if i_knows else '-'} {psk}")
    resp.ok(f"init {protocol} responder {prologue} {r_keys[0] if r_keys else '-'} {i_keys[1] if r_knows else '-'} {psk}")

    writer, reader = init, resp
    hashes = {}
    for index in range(MESSAGE_COUNT[pattern]):
        payload = hexify(os.urandom(index * 7))
        written = writer.ok(f"write {payload}")
        read = reader.ok(f"read {written[0]}")
        if read[0] != payload:
            raise Failure(f"{protocol} {pattern}: handshake payload {index} mismatch")
        final = index == MESSAGE_COUNT[pattern] - 1
        if (len(written) > 1) != final or (len(read) > 1) != final:
            raise Failure(f"{protocol} {pattern}: 'done' reported at the wrong message ({index})")
        if final:
            hashes[writer.name] = written[2]
            hashes[reader.name] = read[2]
        writer, reader = reader, writer

    if hashes[init.name] != hashes[resp.name]:
        raise Failure(f"{protocol} {pattern}: handshake hashes differ")
    if init.ok("hash")[0] != hashes[init.name] or resp.ok("hash")[0] != hashes[resp.name]:
        raise Failure(f"{protocol} {pattern}: 'hash' disagrees with 'done'")

    expected_i = r_keys[1] if r_static else "-"
    expected_r = i_keys[1] if i_static else "-"
    if init.ok("remote-static")[0] != expected_i:
        raise Failure(f"{protocol} {pattern}: initiator remote static key is wrong")
    if resp.ok("remote-static")[0] != expected_r:
        raise Failure(f"{protocol} {pattern}: responder remote static key is wrong")

    def exchange(a, b, size):
        payload = hexify(os.urandom(size))
        message = a.ok(f"write {payload}")[0]
        if b.ok(f"read {message}")[0] != payload:
            raise Failure(f"{protocol} {pattern}: transport payload mismatch {a.name}->{b.name}")

    exchange(init, resp, 100)
    if pattern not in ONE_WAY:
        exchange(resp, init, 200)

    init.ok("rekey send")
    resp.ok("rekey receive")
    exchange(init, resp, 33)
    if pattern not in ONE_WAY:
        resp.ok("rekey send")
        init.ok("rekey receive")
        exchange(resp, init, 44)

    # A tampered transport message is rejected and leaves the transport usable.
    payload = hexify(os.urandom(50))
    message = bytearray.fromhex(init.ok(f"write {payload}")[0])
    message[3] ^= 0xFF
    resp.expect_error(f"read {message.hex()}", "authenticationFailed")
    message[3] ^= 0xFF
    if resp.ok(f"read {message.hex()}")[0] != payload:
        raise Failure(f"{protocol} {pattern}: transport unusable after a rejected message")

    if pattern in ONE_WAY:
        resp.expect_error("write 00", "invalidState")
        init.expect_error("read 00", "invalidState")
        resp.expect_error("rekey send", "invalidState")
        init.expect_error("rekey receive", "invalidState")


def suites(full):
    dhs = DHS_FULL if full else ["25519"]
    hashes = HASHES_FULL if full else HASHES_SWIFT
    return [f"{dh}_{cipher}_{hash_}" for dh in dhs for cipher in CIPHERS for hash_ in hashes]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pairs", help="comma-separated initiator:responder pairs, e.g. csharp:swift")
    parser.add_argument("--skip-build", action="store_true")
    args = parser.parse_args()

    names = list(DRIVERS)
    pairs = [(a, b) for a in names for b in names]
    if args.pairs:
        pairs = [tuple(p.split(":")) for p in args.pairs.split(",")]

    if not args.skip_build:
        for name in sorted({n for pair in pairs for n in pair}):
            print(f"building {name} driver ...", flush=True)
            subprocess.run(DRIVERS[name]["build"], cwd=ROOT, check=True)

    total = failures = 0
    for a, b in pairs:
        init, resp = Driver(a), Driver(b)
        full = DRIVERS[a]["full"] and DRIVERS[b]["full"]
        runs = 0
        try:
            for suite in suites(full):
                for pattern in PATTERNS:
                    protocol = f"Noise_{pattern}_{suite}"
                    try:
                        run_session(init, resp, protocol, pattern)
                    except Failure as e:
                        failures += 1
                        print(f"FAIL {a}->{b} {protocol}: {e}")
                    runs += 1
        finally:
            init.close()
            resp.close()
        total += runs
        print(f"{a}->{b}: {runs} runs, {len(suites(full))} suites x {len(PATTERNS)} patterns")

    print(f"total: {total} runs, {failures} failures")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
