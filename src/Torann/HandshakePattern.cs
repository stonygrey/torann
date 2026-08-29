// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

namespace Torann;

internal enum Token
{
    E,
    S,
    Ee,
    Es,
    Se,
    Ss,
    Psk,
}

/// <summary>
/// A Noise handshake pattern: pre-message tokens for each party plus the
/// sequence of message patterns, per §7 of the Noise specification.
/// </summary>
internal sealed class HandshakePattern
{
    internal string Name { get; }
    internal Token[] PreInitiator { get; }
    internal Token[] PreResponder { get; }
    internal Token[][] Messages { get; }

    private HandshakePattern(string name, Token[] preInitiator, Token[] preResponder, Token[][] messages)
    {
        Name = name;
        PreInitiator = preInitiator;
        PreResponder = preResponder;
        Messages = messages;
    }

    // ---- One-way patterns (§7.4): a single message, transport is
    //      initiator-to-responder only. ----

    internal static readonly HandshakePattern N = new("N",
        [], [Token.S],
        [[Token.E, Token.Es]]);

    internal static readonly HandshakePattern K = new("K",
        [Token.S], [Token.S],
        [[Token.E, Token.Es, Token.Ss]]);

    internal static readonly HandshakePattern X = new("X",
        [], [Token.S],
        [[Token.E, Token.Es, Token.S, Token.Ss]]);

    // ---- Fundamental interactive patterns (§7.5). ----

    internal static readonly HandshakePattern NN = new("NN",
        [], [],
        [[Token.E], [Token.E, Token.Ee]]);

    internal static readonly HandshakePattern NK = new("NK",
        [], [Token.S],
        [[Token.E, Token.Es], [Token.E, Token.Ee]]);

    internal static readonly HandshakePattern NX = new("NX",
        [], [],
        [[Token.E], [Token.E, Token.Ee, Token.S, Token.Es]]);

    internal static readonly HandshakePattern KN = new("KN",
        [Token.S], [],
        [[Token.E], [Token.E, Token.Ee, Token.Se]]);

    internal static readonly HandshakePattern KK = new("KK",
        [Token.S], [Token.S],
        [[Token.E, Token.Es, Token.Ss], [Token.E, Token.Ee, Token.Se]]);

    internal static readonly HandshakePattern KX = new("KX",
        [Token.S], [],
        [[Token.E], [Token.E, Token.Ee, Token.Se, Token.S, Token.Es]]);

    internal static readonly HandshakePattern XN = new("XN",
        [], [],
        [[Token.E], [Token.E, Token.Ee], [Token.S, Token.Se]]);

    internal static readonly HandshakePattern XK = new("XK",
        [], [Token.S],
        [[Token.E, Token.Es], [Token.E, Token.Ee], [Token.S, Token.Se]]);

    internal static readonly HandshakePattern XX = new("XX",
        [], [],
        [[Token.E], [Token.E, Token.Ee, Token.S, Token.Es], [Token.S, Token.Se]]);

    internal static readonly HandshakePattern IN = new("IN",
        [], [],
        [[Token.E, Token.S], [Token.E, Token.Ee, Token.Se]]);

    internal static readonly HandshakePattern IK = new("IK",
        [], [Token.S],
        [[Token.E, Token.Es, Token.S, Token.Ss], [Token.E, Token.Ee, Token.Se]]);

    internal static readonly HandshakePattern IX = new("IX",
        [], [],
        [[Token.E, Token.S], [Token.E, Token.Ee, Token.Se, Token.S, Token.Es]]);

    // ---- Deferred patterns (§7.6): a "1" after a party's letter delays
    //      that party's authentication DH by one message. ----

    internal static readonly HandshakePattern NK1 = new("NK1",
        [], [Token.S],
        [[Token.E], [Token.E, Token.Ee, Token.Es]]);

    internal static readonly HandshakePattern NX1 = new("NX1",
        [], [],
        [[Token.E], [Token.E, Token.Ee, Token.S], [Token.Es]]);

    internal static readonly HandshakePattern X1N = new("X1N",
        [], [],
        [[Token.E], [Token.E, Token.Ee], [Token.S], [Token.Se]]);

    internal static readonly HandshakePattern X1K = new("X1K",
        [], [Token.S],
        [[Token.E, Token.Es], [Token.E, Token.Ee], [Token.S], [Token.Se]]);

    internal static readonly HandshakePattern XK1 = new("XK1",
        [], [Token.S],
        [[Token.E], [Token.E, Token.Ee, Token.Es], [Token.S, Token.Se]]);

    internal static readonly HandshakePattern X1K1 = new("X1K1",
        [], [Token.S],
        [[Token.E], [Token.E, Token.Ee, Token.Es], [Token.S], [Token.Se]]);

    internal static readonly HandshakePattern X1X = new("X1X",
        [], [],
        [[Token.E], [Token.E, Token.Ee, Token.S, Token.Es], [Token.S], [Token.Se]]);

    internal static readonly HandshakePattern XX1 = new("XX1",
        [], [],
        [[Token.E], [Token.E, Token.Ee, Token.S], [Token.Es, Token.S, Token.Se]]);

    internal static readonly HandshakePattern X1X1 = new("X1X1",
        [], [],
        [[Token.E], [Token.E, Token.Ee, Token.S], [Token.Es, Token.S], [Token.Se]]);

    internal static readonly HandshakePattern K1N = new("K1N",
        [Token.S], [],
        [[Token.E], [Token.E, Token.Ee], [Token.Se]]);

    internal static readonly HandshakePattern K1K = new("K1K",
        [Token.S], [Token.S],
        [[Token.E, Token.Es], [Token.E, Token.Ee], [Token.Se]]);

    internal static readonly HandshakePattern KK1 = new("KK1",
        [Token.S], [Token.S],
        [[Token.E], [Token.E, Token.Ee, Token.Se, Token.Es]]);

    internal static readonly HandshakePattern K1K1 = new("K1K1",
        [Token.S], [Token.S],
        [[Token.E], [Token.E, Token.Ee, Token.Es], [Token.Se]]);

    internal static readonly HandshakePattern K1X = new("K1X",
        [Token.S], [],
        [[Token.E], [Token.E, Token.Ee, Token.S, Token.Es], [Token.Se]]);

    internal static readonly HandshakePattern KX1 = new("KX1",
        [Token.S], [],
        [[Token.E], [Token.E, Token.Ee, Token.Se, Token.S], [Token.Es]]);

    internal static readonly HandshakePattern K1X1 = new("K1X1",
        [Token.S], [],
        [[Token.E], [Token.E, Token.Ee, Token.S], [Token.Se, Token.Es]]);

    internal static readonly HandshakePattern I1N = new("I1N",
        [], [],
        [[Token.E, Token.S], [Token.E, Token.Ee], [Token.Se]]);

    internal static readonly HandshakePattern I1K = new("I1K",
        [], [Token.S],
        [[Token.E, Token.Es, Token.S], [Token.E, Token.Ee], [Token.Se]]);

    internal static readonly HandshakePattern IK1 = new("IK1",
        [], [Token.S],
        [[Token.E, Token.S], [Token.E, Token.Ee, Token.Se, Token.Es]]);

    internal static readonly HandshakePattern I1K1 = new("I1K1",
        [], [Token.S],
        [[Token.E, Token.S], [Token.E, Token.Ee, Token.Es], [Token.Se]]);

    internal static readonly HandshakePattern I1X = new("I1X",
        [], [],
        [[Token.E, Token.S], [Token.E, Token.Ee, Token.S, Token.Es], [Token.Se]]);

    internal static readonly HandshakePattern IX1 = new("IX1",
        [], [],
        [[Token.E, Token.S], [Token.E, Token.Ee, Token.Se, Token.S], [Token.Es]]);

    internal static readonly HandshakePattern I1X1 = new("I1X1",
        [], [],
        [[Token.E, Token.S], [Token.E, Token.Ee, Token.S], [Token.Se, Token.Es]]);

    private static readonly Dictionary<string, HandshakePattern> Registry =
        new HandshakePattern[]
        {
            N, K, X,
            NN, NK, NX, KN, KK, KX, XN, XK, XX, IN, IK, IX,
            NK1, NX1, X1N, X1K, XK1, X1K1, X1X, XX1, X1X1,
            K1N, K1K, KK1, K1K1, K1X, KX1, K1X1,
            I1N, I1K, IK1, I1K1, I1X, IX1, I1X1,
        }.ToDictionary(p => p.Name);

    internal static bool TryGet(string name, out HandshakePattern pattern) =>
        Registry.TryGetValue(name, out pattern!);

    internal bool HasInitiatorPreStatic => Contains(PreInitiator, Token.S);

    internal bool HasResponderPreStatic => Contains(PreResponder, Token.S);

    internal bool InitiatorSendsStatic =>
        HasInitiatorPreStatic || Messages.Where((_, i) => i % 2 == 0).Any(m => Contains(m, Token.S));

    internal bool ResponderSendsStatic =>
        HasResponderPreStatic || Messages.Where((_, i) => i % 2 == 1).Any(m => Contains(m, Token.S));

    private static bool Contains(Token[] tokens, Token token)
    {
        foreach (var t in tokens)
        {
            if (t == token)
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>Applies psk0/pskN modifiers, returning a new pattern with psk tokens inserted.</summary>
    internal HandshakePattern WithPsks(IReadOnlyList<int> positions)
    {
        if (positions.Count == 0)
        {
            return this;
        }

        var messages = Messages.Select(m => m.ToList()).ToList();
        foreach (var position in positions)
        {
            if (position == 0)
            {
                messages[0].Insert(0, Token.Psk);
            }
            else if (position <= messages.Count)
            {
                messages[position - 1].Add(Token.Psk);
            }
            else
            {
                throw new NotSupportedException($"psk{position} is out of range for pattern {Name}.");
            }
        }

        return new HandshakePattern(Name, PreInitiator, PreResponder, messages.Select(m => m.ToArray()).ToArray());
    }
}
