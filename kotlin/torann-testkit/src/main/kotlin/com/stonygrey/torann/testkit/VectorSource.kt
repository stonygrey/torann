// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann.testkit

import java.io.File

/** Supplies the text of a vector file. The JVM reads `vectors/`; Android reads assets. */
fun interface VectorSource {
    fun read(fileName: String): String
}

/** Reads vector files from a directory, for the JVM test suite. */
class FileVectorSource(private val directory: File) : VectorSource {
    override fun read(fileName: String): String = File(directory, fileName).readText()
}

fun hexToBytes(hex: String): ByteArray {
    require(hex.length % 2 == 0) { "odd hex length" }
    return ByteArray(hex.length / 2) { hex.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
}

fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
