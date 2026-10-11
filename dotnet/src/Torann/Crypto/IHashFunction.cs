// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Torann.Crypto;

internal interface IHashFunction
{
    string Name { get; }
    int HashLen { get; }
    int BlockLen { get; }

    /// <summary>Computes HASH(a || b) into <paramref name="destination"/>.</summary>
    void Hash(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination);

    /// <summary>Computes HMAC(key, a || b) into <paramref name="destination"/>.</summary>
    void Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination);
}

internal sealed class ShaHash : IHashFunction
{
    internal static readonly ShaHash Sha256 = new("SHA256", HashAlgorithmName.SHA256, 32, 64);
    internal static readonly ShaHash Sha512 = new("SHA512", HashAlgorithmName.SHA512, 64, 128);

    private readonly HashAlgorithmName _algorithm;

    private ShaHash(string name, HashAlgorithmName algorithm, int hashLen, int blockLen)
    {
        Name = name;
        _algorithm = algorithm;
        HashLen = hashLen;
        BlockLen = blockLen;
    }

    public string Name { get; }
    public int HashLen { get; }
    public int BlockLen { get; }

    public void Hash(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination)
    {
        using var hash = IncrementalHash.CreateHash(_algorithm);
        hash.AppendData(a);
        if (!b.IsEmpty)
        {
            hash.AppendData(b);
        }

        hash.GetHashAndReset(destination);
    }

    public void Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination)
    {
        using var hmac = IncrementalHash.CreateHMAC(_algorithm, key);
        hmac.AppendData(a);
        if (!b.IsEmpty)
        {
            hmac.AppendData(b);
        }

        hmac.GetHashAndReset(destination);
    }
}
