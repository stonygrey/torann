// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// The Kotlin interop driver. It reads one command per line from stdin and writes one
// response line per command, following the protocol in interop/README.md.

package com.stonygrey.torann.interop

import com.stonygrey.torann.HandshakeState
import com.stonygrey.torann.NoiseProtocol
import com.stonygrey.torann.TorannException
import com.stonygrey.torann.Transport

fun hex(bytes: ByteArray?): String =
    if (bytes == null || bytes.isEmpty()) "-" else bytes.joinToString("") { "%02x".format(it) }

fun unhex(s: String): ByteArray =
    if (s == "-") ByteArray(0) else ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

fun category(e: Throwable): String = when (e) {
    is TorannException.InvalidProtocolName -> "invalidProtocolName"
    is TorannException.UnsupportedFunction -> "unsupportedFunction"
    is TorannException.InvalidArgument -> "invalidArgument"
    is TorannException.InvalidState -> "invalidState"
    is TorannException.AuthenticationFailed -> "authenticationFailed"
    is TorannException.Closed -> "closed"
    else -> "invalidState"
}

class Session {
    private var handshake: HandshakeState? = null
    private var transport: Transport? = null
    private var handshakeHash: ByteArray? = null

    fun execute(parts: List<String>): String = when (parts[0]) {
        "keygen" -> {
            val keys = NoiseProtocol.parse(parts[1]).generateKeyPair()
            try {
                "ok ${hex(keys.privateKey)} ${hex(keys.publicKey)}"
            } finally {
                keys.close()
            }
        }
        "init" -> {
            reset()
            val protocol = NoiseProtocol.parse(parts[1])
            val local = if (parts[4] == "-") null else protocol.createKeyPair(unhex(parts[4]))
            try {
                handshake = protocol.createHandshake(
                    initiator = parts[2] == "initiator",
                    prologue = unhex(parts[3]),
                    localStatic = local,
                    remoteStatic = if (parts[5] == "-") null else unhex(parts[5]),
                    psks = if (parts[6] == "-") emptyList() else parts[6].split(',').map(::unhex),
                )
            } finally {
                local?.close()
            }
            "ok"
        }
        "write" -> {
            val payload = unhex(parts[1])
            val t = transport
            if (t != null) {
                "ok ${hex(t.writeMessage(payload))}"
            } else {
                val result = requireHandshake().writeMessage(payload)
                if (complete(result.handshakeHash, result.transport)) "ok ${hex(result.message)} done ${hex(handshakeHash)}" else "ok ${hex(result.message)}"
            }
        }
        "read" -> {
            val message = unhex(parts[1])
            val t = transport
            if (t != null) {
                "ok ${hex(t.readMessage(message))}"
            } else {
                val result = requireHandshake().readMessage(message)
                if (complete(result.handshakeHash, result.transport)) "ok ${hex(result.payload)} done ${hex(handshakeHash)}" else "ok ${hex(result.payload)}"
            }
        }
        "rekey" -> {
            val t = requireTransport()
            if (parts[1] == "send") t.rekeySend() else t.rekeyReceive()
            "ok"
        }
        "hash" -> "ok ${hex(handshakeHash ?: throw TorannException.InvalidState("The handshake is not complete."))}"
        "remote-static" -> "ok ${hex(requireHandshake().remoteStaticPublicKey)}"
        else -> throw TorannException.InvalidArgument("Unknown command '${parts[0]}'.")
    }

    private fun requireHandshake(): HandshakeState = handshake ?: throw TorannException.InvalidState("No session; send init first.")

    private fun requireTransport(): Transport = transport ?: throw TorannException.InvalidState("The handshake is not complete.")

    private fun complete(hash: ByteArray?, t: Transport?): Boolean {
        if (t == null) return false
        transport = t
        handshakeHash = hash
        return true
    }

    private fun reset() {
        handshake?.close()
        transport?.close()
        handshake = null
        transport = null
        handshakeHash = null
    }
}

fun main() {
    val session = Session()
    while (true) {
        val line = readLine() ?: break
        val parts = line.trim().split(' ').filter { it.isNotEmpty() }
        if (parts.isEmpty()) continue
        if (parts[0] == "quit") {
            println("ok")
            break
        }
        try {
            println(session.execute(parts))
        } catch (e: Throwable) {
            println("error ${category(e)} ${(e.message ?: e.toString()).replace('\n', ' ')}")
        }
        System.out.flush()
    }
}
