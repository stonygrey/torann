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

    internal static readonly HandshakePattern NN = new("NN",
        [], [],
        [[Token.E], [Token.E, Token.Ee]]);

    internal static readonly HandshakePattern NK = new("NK",
        [], [Token.S],
        [[Token.E, Token.Es], [Token.E, Token.Ee]]);

    internal static readonly HandshakePattern KK = new("KK",
        [Token.S], [Token.S],
        [[Token.E, Token.Es, Token.Ss], [Token.E, Token.Ee, Token.Se]]);

    internal static readonly HandshakePattern XX = new("XX",
        [], [],
        [[Token.E], [Token.E, Token.Ee, Token.S, Token.Es], [Token.S, Token.Se]]);

    internal static readonly HandshakePattern IK = new("IK",
        [], [Token.S],
        [[Token.E, Token.Es, Token.S, Token.Ss], [Token.E, Token.Ee, Token.Se]]);

    private static readonly Dictionary<string, HandshakePattern> Registry = new()
    {
        [NN.Name] = NN,
        [NK.Name] = NK,
        [KK.Name] = KK,
        [XX.Name] = XX,
        [IK.Name] = IK,
    };

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
