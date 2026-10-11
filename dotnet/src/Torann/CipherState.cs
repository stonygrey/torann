// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using Torann.Crypto;

namespace Torann;

/// <summary>CipherState per Noise §5.1: an AEAD key plus a 64-bit nonce counter.</summary>
internal sealed class CipherState : IDisposable
{
    private readonly ICipherFunction _cipherFunction;
    private ICipherKey? _key;
    private ulong _nonce;
    private bool _disposed;

    internal CipherState(ICipherFunction cipherFunction) => _cipherFunction = cipherFunction;

    internal bool HasKey => !_disposed && _key != null;

    internal void InitializeKey(ReadOnlySpan<byte> key)
    {
        ThrowIfDisposed();
        _key?.Dispose();
        _key = _cipherFunction.CreateKey(key);
        _nonce = 0;
    }

    internal void SetNonce(ulong nonce)
    {
        ThrowIfDisposed();
        if (nonce == ulong.MaxValue)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce), "Nonce 2^64-1 is reserved.");
        }

        _nonce = nonce;
    }

    /// <summary>Rekey per Noise §11.3 / §4.2. Replaces k; does not reset n.</summary>
    internal void Rekey()
    {
        ThrowIfDisposed();
        if (_key == null)
        {
            throw new InvalidOperationException("Cannot rekey an empty CipherState.");
        }

        Span<byte> zeros = stackalloc byte[32];
        Span<byte> output = stackalloc byte[48];
        _key.Encrypt(ulong.MaxValue, default, zeros, output);

        var nonce = _nonce;
        _key.Dispose();
        _key = _cipherFunction.CreateKey(output[..32]);
        _nonce = nonce;
        CryptographicOperations.ZeroMemory(output);
    }

    internal int EncryptWithAd(ReadOnlySpan<byte> ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
    {
        ThrowIfDisposed();
        if (_key == null)
        {
            plaintext.CopyTo(ciphertext);
            return plaintext.Length;
        }

        CheckNonce();
        var length = _key.Encrypt(_nonce, ad, plaintext, ciphertext);
        _nonce++;
        return length;
    }

    internal int DecryptWithAd(ReadOnlySpan<byte> ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
    {
        ThrowIfDisposed();
        if (_key == null)
        {
            ciphertext.CopyTo(plaintext);
            return ciphertext.Length;
        }

        if (ciphertext.Length < 16)
        {
            throw new CryptographicException("Ciphertext is shorter than the authentication tag.");
        }

        CheckNonce();
        int length;
        try
        {
            length = _key.Decrypt(_nonce, ad, ciphertext, plaintext);
        }
        catch (CryptographicException)
        {
            // The fixed message replaces the provider's text so that no provider text crosses the API.
            throw new AuthenticationTagMismatchException("The authentication tag did not match.");
        }

        _nonce++;
        return length;
    }

    private void CheckNonce()
    {
        // 2^64 - 1 is reserved (Noise §5.1); rekey or a new session is required first.
        if (_nonce == ulong.MaxValue)
        {
            throw new InvalidOperationException("Nonce exhausted; the session must be re-established.");
        }
    }

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _key?.Dispose();
        _key = null;
    }
}
