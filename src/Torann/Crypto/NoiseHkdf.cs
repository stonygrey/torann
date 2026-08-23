// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Torann.Crypto;

/// <summary>
/// The HKDF variant defined in Noise §4.3 (two or three full-hash-length
/// outputs, no info parameter). Not interchangeable with RFC 5869 HKDF.
/// </summary>
internal static class NoiseHkdf
{
    /// <summary>
    /// Computes 2 or 3 HKDF outputs, each HashLen bytes. Pass an empty span for
    /// <paramref name="output3"/> to compute only two.
    /// </summary>
    internal static void Hkdf(
        IHashFunction hash,
        ReadOnlySpan<byte> chainingKey,
        ReadOnlySpan<byte> inputKeyMaterial,
        Span<byte> output1,
        Span<byte> output2,
        Span<byte> output3)
    {
        Span<byte> tempKey = stackalloc byte[hash.HashLen];
        ReadOnlySpan<byte> one = [0x01];
        ReadOnlySpan<byte> two = [0x02];
        ReadOnlySpan<byte> three = [0x03];

        hash.Hmac(chainingKey, inputKeyMaterial, default, tempKey);
        hash.Hmac(tempKey, one, default, output1);
        hash.Hmac(tempKey, output1, two, output2);
        if (!output3.IsEmpty)
        {
            hash.Hmac(tempKey, output2, three, output3);
        }

        CryptographicOperations.ZeroMemory(tempKey);
    }
}
