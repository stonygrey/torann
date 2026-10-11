// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using System.Text;
using Torann.Crypto;

namespace Torann;

/// <summary>SymmetricState per Noise §5.2: chaining key, handshake hash, and inner CipherState.</summary>
internal sealed class SymmetricState : IDisposable
{
    private readonly IHashFunction _hash;
    private readonly ICipherFunction _cipherFunction;
    private readonly CipherState _cipherState;
    private readonly byte[] _ck;
    private readonly byte[] _h;

    internal SymmetricState(string protocolName, ICipherFunction cipherFunction, IHashFunction hash)
    {
        _hash = hash;
        _cipherFunction = cipherFunction;
        _cipherState = new CipherState(cipherFunction);
        _ck = new byte[hash.HashLen];
        _h = new byte[hash.HashLen];

        var name = Encoding.ASCII.GetBytes(protocolName);
        if (name.Length <= hash.HashLen)
        {
            name.CopyTo(_h, 0);
        }
        else
        {
            hash.Hash(name, default, _h);
        }

        _h.CopyTo(_ck, 0);
    }

    internal bool CipherHasKey => _cipherState.HasKey;

    internal void MixHash(ReadOnlySpan<byte> data) => _hash.Hash(_h, data, _h);

    internal void MixKey(ReadOnlySpan<byte> inputKeyMaterial)
    {
        Span<byte> output1 = stackalloc byte[_hash.HashLen];
        Span<byte> output2 = stackalloc byte[_hash.HashLen];
        NoiseHkdf.Hkdf(_hash, _ck, inputKeyMaterial, output1, output2, default);
        output1.CopyTo(_ck);
        _cipherState.InitializeKey(output2[..32]);
        CryptographicOperations.ZeroMemory(output1);
        CryptographicOperations.ZeroMemory(output2);
    }

    internal void MixKeyAndHash(ReadOnlySpan<byte> inputKeyMaterial)
    {
        Span<byte> output1 = stackalloc byte[_hash.HashLen];
        Span<byte> output2 = stackalloc byte[_hash.HashLen];
        Span<byte> output3 = stackalloc byte[_hash.HashLen];
        NoiseHkdf.Hkdf(_hash, _ck, inputKeyMaterial, output1, output2, output3);
        output1.CopyTo(_ck);
        MixHash(output2);
        _cipherState.InitializeKey(output3[..32]);
        CryptographicOperations.ZeroMemory(output1);
        CryptographicOperations.ZeroMemory(output2);
        CryptographicOperations.ZeroMemory(output3);
    }

    internal int EncryptAndHash(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
    {
        var length = _cipherState.EncryptWithAd(_h, plaintext, ciphertext);
        MixHash(ciphertext[..length]);
        return length;
    }

    internal int DecryptAndHash(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        var length = _cipherState.DecryptWithAd(_h, ciphertext, plaintext);
        MixHash(ciphertext);
        return length;
    }

    internal (CipherState C1, CipherState C2) Split()
    {
        Span<byte> output1 = stackalloc byte[_hash.HashLen];
        Span<byte> output2 = stackalloc byte[_hash.HashLen];
        NoiseHkdf.Hkdf(_hash, _ck, default, output1, output2, default);

        var c1 = new CipherState(_cipherFunction);
        c1.InitializeKey(output1[..32]);
        var c2 = new CipherState(_cipherFunction);
        c2.InitializeKey(output2[..32]);

        CryptographicOperations.ZeroMemory(output1);
        CryptographicOperations.ZeroMemory(output2);
        return (c1, c2);
    }

    internal byte[] GetHandshakeHash() => (byte[])_h.Clone();

    /// <summary>Zeros ck and the handshake CipherState after Split, leaving h for channel binding.</summary>
    internal void ClearSecrets()
    {
        _cipherState.Dispose();
        CryptographicOperations.ZeroMemory(_ck);
    }

    public void Dispose()
    {
        _cipherState.Dispose();
        CryptographicOperations.ZeroMemory(_ck);
    }
}
