// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann.testkit

import com.stonygrey.torann.HandshakeState
import com.stonygrey.torann.NoiseProtocol
import com.stonygrey.torann.TorannException
import com.stonygrey.torann.TorannTestApi
import com.stonygrey.torann.Transport
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.fail
import org.junit.Test

/**
 * Runs the shared vectors with their fixed keys; every message and every handshake hash
 * must match byte for byte. Every function in both files is supported, so the runner
 * asserts that 944 and 408 vectors ran with none skipped. The JVM suite and the Android
 * instrumented suite extend this class with their own [VectorSource].
 */
@OptIn(TorannTestApi::class)
abstract class VectorTests(private val source: VectorSource) {
    @Test
    fun cacophonyVectors() = runFile("cacophony.txt", expectedRun = 944, expectedSkipped = 0)

    @Test
    fun snowVectors() = runFile("snow.txt", expectedRun = 408, expectedSkipped = 0)

    private fun runFile(fileName: String, expectedRun: Int, expectedSkipped: Int) {
        @Suppress("UNCHECKED_CAST")
        val file = MiniJson.parse(source.read(fileName)) as Map<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val vectors = file["vectors"] as List<Map<String, Any?>>
        var run = 0
        var skipped = 0

        for (vector in vectors) {
            val name = vector["protocol_name"] as String
            val protocol = try {
                NoiseProtocol.parse(name)
            } catch (_: TorannException.UnsupportedFunction) {
                skipped++
                continue
            }

            try {
                runVector(protocol, vector)
            } catch (e: Throwable) {
                fail("Vector '$name' failed: $e")
            }
            run++
        }

        println("$fileName: ran $run vectors, skipped $skipped unsupported.")
        assertEquals("$fileName: run count", expectedRun, run)
        assertEquals("$fileName: skipped count", expectedSkipped, skipped)
    }

    private fun string(vector: Map<String, Any?>, key: String): String? = vector[key] as String?

    @Suppress("UNCHECKED_CAST")
    private fun psks(vector: Map<String, Any?>, key: String): List<ByteArray> =
        (vector[key] as List<String>?)?.map(::hexToBytes) ?: emptyList()

    private fun runVector(protocol: NoiseProtocol, vector: Map<String, Any?>) {
        val name = string(vector, "protocol_name")!!
        val initStatic = string(vector, "init_static")?.let { protocol.createKeyPair(hexToBytes(it)) }
        val respStatic = string(vector, "resp_static")?.let { protocol.createKeyPair(hexToBytes(it)) }

        val initiator = protocol.createHandshake(
            initiator = true,
            prologue = hexToBytes(string(vector, "init_prologue")!!),
            localStatic = initStatic,
            remoteStatic = string(vector, "init_remote_static")?.let(::hexToBytes),
            psks = psks(vector, "init_psks"),
        )
        string(vector, "init_ephemeral")?.let { initiator.setFixedEphemeral(hexToBytes(it)) }

        val responder = protocol.createHandshake(
            initiator = false,
            prologue = hexToBytes(string(vector, "resp_prologue")!!),
            localStatic = respStatic,
            remoteStatic = string(vector, "resp_remote_static")?.let(::hexToBytes),
            psks = psks(vector, "resp_psks"),
        )
        string(vector, "resp_ephemeral")?.let { responder.setFixedEphemeral(hexToBytes(it)) }

        var initTransport: Transport? = null
        var respTransport: Transport? = null
        var oneWay = false

        @Suppress("UNCHECKED_CAST")
        val messages = vector["messages"] as List<Map<String, Any?>>
        try {
            for ((i, message) in messages.withIndex()) {
                val payload = hexToBytes(message["payload"] as String)
                val expected = hexToBytes(message["ciphertext"] as String)
                val initiatorSends = oneWay || i % 2 == 0

                val it = initTransport
                val rt = respTransport
                if (it != null && rt != null) {
                    val writer = if (initiatorSends) it else rt
                    val reader = if (initiatorSends) rt else it
                    assertEquals("$name transport message $i", bytesToHex(expected), bytesToHex(writer.writeMessage(payload)))
                    assertEquals("$name transport payload $i", bytesToHex(payload), bytesToHex(reader.readMessage(expected)))
                    continue
                }

                val writer: HandshakeState = if (initiatorSends) initiator else responder
                val reader: HandshakeState = if (initiatorSends) responder else initiator
                val written = writer.writeMessage(payload)
                assertEquals("$name message $i", bytesToHex(expected), bytesToHex(written.message))
                val read = reader.readMessage(expected)
                assertEquals("$name payload $i", bytesToHex(payload), bytesToHex(read.payload))

                val writerTransport = written.transport
                if (writerTransport != null) {
                    val readerTransport = read.transport
                    assertNotNull("$name: reader produced no transport", readerTransport)
                    initTransport = if (initiatorSends) writerTransport else readerTransport
                    respTransport = if (initiatorSends) readerTransport else writerTransport
                    if (i == 0) oneWay = true

                    assertNotNull(written.handshakeHash)
                    assertNotNull(read.handshakeHash)
                    assertEquals("$name handshake hashes differ", bytesToHex(written.handshakeHash!!), bytesToHex(read.handshakeHash!!))
                    string(vector, "handshake_hash")?.let {
                        assertEquals("$name handshake hash", it, bytesToHex(written.handshakeHash!!))
                    }
                } else {
                    assertNull(read.transport)
                    assertNull(written.handshakeHash)
                }
            }
        } finally {
            initTransport?.close()
            respTransport?.close()
            initiator.close()
            responder.close()
            initStatic?.close()
            respStatic?.close()
        }
    }
}
