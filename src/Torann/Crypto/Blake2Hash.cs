// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace Torann.Crypto;

/// <summary>
/// BLAKE2s and BLAKE2b per RFC 7693, backed by Bouncy Castle's managed
/// digests. Noise uses the HMAC construction with BLAKE2 (spec §4.3, §12.5)
/// rather than BLAKE2's own keyed mode; Bouncy Castle's generic HMac handles
/// the 64/128-byte block sizes.
/// </summary>
internal sealed class Blake2Hash : IHashFunction
{
    internal static readonly Blake2Hash Blake2s = new("BLAKE2s", 32, 64);
    internal static readonly Blake2Hash Blake2b = new("BLAKE2b", 64, 128);

    private Blake2Hash(string name, int hashLen, int blockLen)
    {
        Name = name;
        HashLen = hashLen;
        BlockLen = blockLen;
    }

    public string Name { get; }
    public int HashLen { get; }
    public int BlockLen { get; }

    private IDigest CreateDigest() =>
        HashLen == 32 ? new Blake2sDigest(256) : new Blake2bDigest(512);

    public void Hash(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination)
    {
        var digest = CreateDigest();
        digest.BlockUpdate(a);
        if (!b.IsEmpty)
        {
            digest.BlockUpdate(b);
        }

        var result = new byte[HashLen];
        digest.DoFinal(result, 0);
        result.CopyTo(destination);
    }

    public void Hmac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination)
    {
        var hmac = new HMac(CreateDigest());
        hmac.Init(new KeyParameter(key.ToArray()));
        hmac.BlockUpdate(a);
        if (!b.IsEmpty)
        {
            hmac.BlockUpdate(b);
        }

        var result = new byte[HashLen];
        hmac.DoFinal(result, 0);
        result.CopyTo(destination);
    }
}
