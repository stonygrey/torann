// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

import com.stonygrey.torann.Token.E
import com.stonygrey.torann.Token.EE
import com.stonygrey.torann.Token.ES
import com.stonygrey.torann.Token.PSK
import com.stonygrey.torann.Token.S
import com.stonygrey.torann.Token.SE
import com.stonygrey.torann.Token.SS

internal enum class Token { E, S, EE, ES, SE, SS, PSK }

/**
 * A Noise handshake pattern: pre-message tokens for each party plus the sequence of
 * message patterns (Noise §7).
 */
internal class HandshakePattern(
    val name: String,
    val preInitiator: List<Token>,
    val preResponder: List<Token>,
    val messages: List<List<Token>>,
) {
    val hasInitiatorPreStatic: Boolean get() = S in preInitiator
    val hasResponderPreStatic: Boolean get() = S in preResponder

    val initiatorSendsStatic: Boolean
        get() = hasInitiatorPreStatic || messages.filterIndexed { i, _ -> i % 2 == 0 }.any { S in it }

    val responderSendsStatic: Boolean
        get() = hasResponderPreStatic || messages.filterIndexed { i, _ -> i % 2 == 1 }.any { S in it }

    /** Applies psk0/pskN modifiers, returning a new pattern with psk tokens inserted. */
    fun withPsks(positions: List<Int>): HandshakePattern {
        if (positions.isEmpty()) return this
        val messages = this.messages.map { it.toMutableList() }
        for (position in positions) {
            when {
                position == 0 -> messages[0].add(0, PSK)
                position <= messages.size -> messages[position - 1].add(PSK)
                else -> throw TorannException.UnsupportedFunction("psk$position is out of range for pattern $name.")
            }
        }
        return HandshakePattern(name, preInitiator, preResponder, messages.map { it.toList() })
    }

    companion object {
        private fun p(name: String, preInitiator: List<Token>, preResponder: List<Token>, vararg messages: List<Token>) =
            HandshakePattern(name, preInitiator, preResponder, messages.toList())

        // One-way patterns (§7.4): a single message, transport is initiator-to-responder only.
        val N = p("N", listOf(), listOf(S), listOf(E, ES))
        val K = p("K", listOf(S), listOf(S), listOf(E, ES, SS))
        val X = p("X", listOf(), listOf(S), listOf(E, ES, S, SS))

        // Fundamental interactive patterns (§7.5).
        val NN = p("NN", listOf(), listOf(), listOf(E), listOf(E, EE))
        val NK = p("NK", listOf(), listOf(S), listOf(E, ES), listOf(E, EE))
        val NX = p("NX", listOf(), listOf(), listOf(E), listOf(E, EE, S, ES))
        val KN = p("KN", listOf(S), listOf(), listOf(E), listOf(E, EE, SE))
        val KK = p("KK", listOf(S), listOf(S), listOf(E, ES, SS), listOf(E, EE, SE))
        val KX = p("KX", listOf(S), listOf(), listOf(E), listOf(E, EE, SE, S, ES))
        val XN = p("XN", listOf(), listOf(), listOf(E), listOf(E, EE), listOf(S, SE))
        val XK = p("XK", listOf(), listOf(S), listOf(E, ES), listOf(E, EE), listOf(S, SE))
        val XX = p("XX", listOf(), listOf(), listOf(E), listOf(E, EE, S, ES), listOf(S, SE))
        val IN = p("IN", listOf(), listOf(), listOf(E, S), listOf(E, EE, SE))
        val IK = p("IK", listOf(), listOf(S), listOf(E, ES, S, SS), listOf(E, EE, SE))
        val IX = p("IX", listOf(), listOf(), listOf(E, S), listOf(E, EE, SE, S, ES))

        // Deferred patterns (§7.6): a "1" after a party's letter delays that party's
        // authentication DH by one message.
        val NK1 = p("NK1", listOf(), listOf(S), listOf(E), listOf(E, EE, ES))
        val NX1 = p("NX1", listOf(), listOf(), listOf(E), listOf(E, EE, S), listOf(ES))
        val X1N = p("X1N", listOf(), listOf(), listOf(E), listOf(E, EE), listOf(S), listOf(SE))
        val X1K = p("X1K", listOf(), listOf(S), listOf(E, ES), listOf(E, EE), listOf(S), listOf(SE))
        val XK1 = p("XK1", listOf(), listOf(S), listOf(E), listOf(E, EE, ES), listOf(S, SE))
        val X1K1 = p("X1K1", listOf(), listOf(S), listOf(E), listOf(E, EE, ES), listOf(S), listOf(SE))
        val X1X = p("X1X", listOf(), listOf(), listOf(E), listOf(E, EE, S, ES), listOf(S), listOf(SE))
        val XX1 = p("XX1", listOf(), listOf(), listOf(E), listOf(E, EE, S), listOf(ES, S, SE))
        val X1X1 = p("X1X1", listOf(), listOf(), listOf(E), listOf(E, EE, S), listOf(ES, S), listOf(SE))
        val K1N = p("K1N", listOf(S), listOf(), listOf(E), listOf(E, EE), listOf(SE))
        val K1K = p("K1K", listOf(S), listOf(S), listOf(E, ES), listOf(E, EE), listOf(SE))
        val KK1 = p("KK1", listOf(S), listOf(S), listOf(E), listOf(E, EE, SE, ES))
        val K1K1 = p("K1K1", listOf(S), listOf(S), listOf(E), listOf(E, EE, ES), listOf(SE))
        val K1X = p("K1X", listOf(S), listOf(), listOf(E), listOf(E, EE, S, ES), listOf(SE))
        val KX1 = p("KX1", listOf(S), listOf(), listOf(E), listOf(E, EE, SE, S), listOf(ES))
        val K1X1 = p("K1X1", listOf(S), listOf(), listOf(E), listOf(E, EE, S), listOf(SE, ES))
        val I1N = p("I1N", listOf(), listOf(), listOf(E, S), listOf(E, EE), listOf(SE))
        val I1K = p("I1K", listOf(), listOf(S), listOf(E, ES, S), listOf(E, EE), listOf(SE))
        val IK1 = p("IK1", listOf(), listOf(S), listOf(E, S), listOf(E, EE, SE, ES))
        val I1K1 = p("I1K1", listOf(), listOf(S), listOf(E, S), listOf(E, EE, ES), listOf(SE))
        val I1X = p("I1X", listOf(), listOf(), listOf(E, S), listOf(E, EE, S, ES), listOf(SE))
        val IX1 = p("IX1", listOf(), listOf(), listOf(E, S), listOf(E, EE, SE, S), listOf(ES))
        val I1X1 = p("I1X1", listOf(), listOf(), listOf(E, S), listOf(E, EE, S), listOf(SE, ES))

        private val registry: Map<String, HandshakePattern> = listOf(
            N, K, X,
            NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX,
            NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1,
            K1N, K1K, KK1, K1K1, K1X, KX1, K1X1,
            I1N, I1K, IK1, I1K1, I1X, IX1, I1X1,
        ).associateBy { it.name }

        fun find(name: String): HandshakePattern? = registry[name]
    }
}
