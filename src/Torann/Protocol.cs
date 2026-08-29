// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using Torann.Crypto;

namespace Torann;

/// <summary>
/// A parsed Noise protocol, e.g. <c>Noise_XX_25519_ChaChaPoly_SHA256</c>.
/// Supported: every one-way, fundamental, and deferred handshake pattern
/// from the Noise specification (with psk modifiers); DH 25519 and 448;
/// ciphers ChaChaPoly and AESGCM; hashes SHA256, SHA512, BLAKE2s, BLAKE2b.
/// </summary>
public sealed class Protocol
{
    /// <summary>Maximum length in bytes of a Noise handshake or transport message (Noise §3).</summary>
    public const int MaxMessageLength = 65535;

    private Protocol(
        string name,
        HandshakePattern pattern,
        ICipherFunction cipher,
        IHashFunction hash,
        IDhFunction dh,
        IReadOnlyList<int> pskPositions)
    {
        Name = name;
        Pattern = pattern;
        Cipher = cipher;
        Hash = hash;
        Dh = dh;
        PskPositions = pskPositions;
    }

    /// <summary>The full protocol name, e.g. <c>Noise_XX_25519_ChaChaPoly_SHA256</c>.</summary>
    public string Name { get; }

    internal HandshakePattern Pattern { get; }
    internal ICipherFunction Cipher { get; }
    internal IHashFunction Hash { get; }
    internal IDhFunction Dh { get; }
    internal IReadOnlyList<int> PskPositions { get; }

    /// <summary>Parses a Noise protocol name such as <c>Noise_XX_25519_ChaChaPoly_SHA256</c>.</summary>
    /// <param name="name">The protocol name: <c>Noise_{pattern}{modifiers}_{dh}_{cipher}_{hash}</c>.</param>
    /// <returns>A <see cref="Protocol"/> ready to create handshakes and key pairs.</returns>
    /// <exception cref="ArgumentException">The name is not well-formed.</exception>
    /// <exception cref="NotSupportedException">The pattern, modifier, DH, cipher, or hash is not supported by Torann.</exception>
    public static Protocol Parse(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        var parts = name.Split('_');
        if (parts.Length != 5 || parts[0] != "Noise")
        {
            throw new ArgumentException($"'{name}' is not a valid Noise protocol name.", nameof(name));
        }

        // Pattern names are uppercase letters plus the deferred-pattern "1"
        // digits (NK1, X1X1); modifiers (psk0, ...) start with a lowercase
        // letter.
        var patternPart = parts[1];
        var split = 0;
        while (split < patternPart.Length &&
               (char.IsAsciiLetterUpper(patternPart[split]) || char.IsAsciiDigit(patternPart[split])))
        {
            split++;
        }

        if (!HandshakePattern.TryGet(patternPart[..split], out var pattern))
        {
            throw new NotSupportedException($"Handshake pattern '{patternPart[..split]}' is not supported.");
        }

        var pskPositions = new List<int>();
        if (split < patternPart.Length)
        {
            foreach (var modifier in patternPart[split..].Split('+'))
            {
                if (modifier.StartsWith("psk", StringComparison.Ordinal) &&
                    int.TryParse(modifier.AsSpan(3), out var position) && position >= 0)
                {
                    pskPositions.Add(position);
                }
                else
                {
                    throw new NotSupportedException($"Pattern modifier '{modifier}' is not supported.");
                }
            }
        }

        pattern = pattern.WithPsks(pskPositions);

        IDhFunction dh = parts[2] switch
        {
            "25519" => new Curve25519Dh(),
            "448" => new Curve448Dh(),
            _ => throw new NotSupportedException($"DH function '{parts[2]}' is not supported."),
        };

        ICipherFunction cipher = parts[3] switch
        {
            "ChaChaPoly" => new ChaChaPolyCipher(),
            "AESGCM" => new AesGcmCipher(),
            _ => throw new NotSupportedException($"Cipher function '{parts[3]}' is not supported."),
        };

        IHashFunction hash = parts[4] switch
        {
            "SHA256" => ShaHash.Sha256,
            "SHA512" => ShaHash.Sha512,
            "BLAKE2s" => Blake2Hash.Blake2s,
            "BLAKE2b" => Blake2Hash.Blake2b,
            _ => throw new NotSupportedException($"Hash function '{parts[4]}' is not supported."),
        };

        return new Protocol(name, pattern, cipher, hash, dh, pskPositions);
    }

    /// <summary>Generates a fresh static key pair for this protocol's DH function.</summary>
    public KeyPair GenerateKeyPair()
    {
        var privateKey = new byte[Dh.DhLen];
        Dh.GeneratePrivateKey(privateKey);
        return CreateKeyPairCore(privateKey);
    }

    /// <summary>Reconstructs a key pair from a stored private key.</summary>
    public KeyPair CreateKeyPair(ReadOnlySpan<byte> privateKey)
    {
        if (privateKey.Length != Dh.DhLen)
        {
            throw new ArgumentException($"The private key must be {Dh.DhLen} bytes.", nameof(privateKey));
        }

        return CreateKeyPairCore(privateKey.ToArray());
    }

    private KeyPair CreateKeyPairCore(byte[] privateKey)
    {
        var publicKey = new byte[Dh.DhLen];
        Dh.DerivePublicKey(privateKey, publicKey);
        return new KeyPair(privateKey, publicKey);
    }

    /// <param name="initiator">True for the party that sends the first handshake message.</param>
    /// <param name="prologue">Optional data both parties must agree on (authenticated, not transmitted).</param>
    /// <param name="s">Local static key pair, required when the pattern sends or pre-shares this party's static.</param>
    /// <param name="remoteStatic">Remote static public key, required when the pattern pre-shares the peer's static.</param>
    /// <param name="psks">32-byte pre-shared keys, one per psk modifier, in handshake processing order.</param>
    public HandshakeState CreateHandshake(
        bool initiator,
        ReadOnlySpan<byte> prologue = default,
        KeyPair? s = null,
        byte[]? remoteStatic = null,
        IEnumerable<byte[]>? psks = null)
    {
        return new HandshakeState(this, initiator, prologue, s, remoteStatic, psks);
    }
}
