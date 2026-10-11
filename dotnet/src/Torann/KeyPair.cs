// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Torann;

/// <summary>A DH key pair. Create via <see cref="NoiseProtocol.GenerateKeyPair"/> or <see cref="NoiseProtocol.CreateKeyPair"/>.</summary>
public sealed class KeyPair : IDisposable
{
    private byte[]? _privateKey;
    private readonly byte[] _publicKey;
    private bool _disposed;

    internal KeyPair(byte[] privateKey, byte[] publicKey)
    {
        _privateKey = privateKey;
        _publicKey = publicKey;
    }

    /// <summary>Private key bytes. Do not store the span after <see cref="Dispose"/>.</summary>
    public ReadOnlySpan<byte> PrivateKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _privateKey;
        }
    }

    /// <summary>A copy of the public key bytes.</summary>
    public byte[] PublicKey
    {
        get
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return (byte[])_publicKey.Clone();
        }
    }

    /// <summary>Zeros the private key. Accessing either key afterwards throws <see cref="ObjectDisposedException"/>.</summary>
    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (_privateKey != null)
        {
            CryptographicOperations.ZeroMemory(_privateKey);
            _privateKey = null;
        }
    }
}
