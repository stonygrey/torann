// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using Org.BouncyCastle.Math.EC.Rfc7748;

namespace Torann.Crypto;

/// <summary>
/// X448 per RFC 7748, backed by Bouncy Castle's fully managed implementation.
/// The raw ScalarMult API is used deliberately: the Noise spec (§12.1) leaves
/// all-zero output checks to the application, and an unconditional throw here
/// would diverge from other Noise implementations.
/// </summary>
internal sealed class Curve448Dh : IDhFunction
{
    public string Name => "448";
    public int DhLen => 56;

    public void GeneratePrivateKey(Span<byte> privateKey) => RandomNumberGenerator.Fill(privateKey);

    public void DerivePublicKey(ReadOnlySpan<byte> privateKey, Span<byte> publicKey)
    {
        var k = privateKey.ToArray();
        var r = new byte[DhLen];
        try
        {
            X448.ScalarMultBase(k, 0, r, 0);
            r.CopyTo(publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(k);
            CryptographicOperations.ZeroMemory(r);
        }
    }

    public void Dh(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey, Span<byte> sharedSecret)
    {
        var k = privateKey.ToArray();
        var u = publicKey.ToArray();
        var r = new byte[DhLen];
        try
        {
            X448.ScalarMult(k, 0, u, 0, r, 0);
            r.CopyTo(sharedSecret);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(k);
            CryptographicOperations.ZeroMemory(u);
            CryptographicOperations.ZeroMemory(r);
        }
    }
}
