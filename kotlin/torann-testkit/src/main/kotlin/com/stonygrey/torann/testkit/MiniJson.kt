// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann.testkit

/**
 * A minimal JSON reader for the vector files, which contain objects, arrays, and
 * strings only. It exists so that the test kit adds no JSON dependency. It returns
 * `Map<String, Any?>`, `List<Any?>`, `String`, `Boolean`, `Double`, or null.
 */
internal class MiniJson private constructor(private val text: String) {
    private var i = 0

    companion object {
        fun parse(text: String): Any? {
            val parser = MiniJson(text)
            val value = parser.value()
            parser.skipWhitespace()
            require(parser.i == text.length) { "trailing characters at ${parser.i}" }
            return value
        }
    }

    private fun skipWhitespace() {
        while (i < text.length && text[i].isWhitespace()) i++
    }

    private fun value(): Any? {
        skipWhitespace()
        return when (text[i]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> str()
            't' -> literal("true", true)
            'f' -> literal("false", false)
            'n' -> literal("null", null)
            else -> number()
        }
    }

    private fun obj(): Map<String, Any?> {
        expect('{')
        val result = LinkedHashMap<String, Any?>()
        skipWhitespace()
        if (text[i] == '}') { i++; return result }
        while (true) {
            skipWhitespace()
            val key = str()
            skipWhitespace()
            expect(':')
            result[key] = value()
            skipWhitespace()
            if (text[i] == ',') { i++; continue }
            expect('}')
            return result
        }
    }

    private fun arr(): List<Any?> {
        expect('[')
        val result = ArrayList<Any?>()
        skipWhitespace()
        if (text[i] == ']') { i++; return result }
        while (true) {
            result.add(value())
            skipWhitespace()
            if (text[i] == ',') { i++; continue }
            expect(']')
            return result
        }
    }

    private fun str(): String {
        expect('"')
        val sb = StringBuilder()
        while (true) {
            val c = text[i++]
            when (c) {
                '"' -> return sb.toString()
                '\\' -> when (val e = text[i++]) {
                    'n' -> sb.append('\n')
                    't' -> sb.append('\t')
                    'r' -> sb.append('\r')
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000C')
                    'u' -> { sb.append(text.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                    else -> sb.append(e)
                }
                else -> sb.append(c)
            }
        }
    }

    private fun literal(word: String, value: Any?): Any? {
        require(text.startsWith(word, i)) { "expected $word at $i" }
        i += word.length
        return value
    }

    private fun number(): Double {
        val start = i
        while (i < text.length && (text[i].isDigit() || text[i] in "+-.eE")) i++
        return text.substring(start, i).toDouble()
    }

    private fun expect(c: Char) {
        require(text[i] == c) { "expected '$c' at $i, found '${text[i]}'" }
        i++
    }
}
