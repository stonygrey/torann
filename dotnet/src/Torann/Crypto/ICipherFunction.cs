// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

namespace Torann.Crypto;

internal interface ICipherFunction
{
    string Name { get; }
    ICipherKey CreateKey(ReadOnlySpan<byte> key);
}

/// <summary>An AEAD cipher bound to a key. Nonce handling follows Noise §4.2.</summary>
internal interface ICipherKey : IDisposable
{
    /// <summary>Encrypts plaintext, appending a 16-byte tag. Returns bytes written.</summary>
    int Encrypt(ulong nonce, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext);

    /// <summary>Decrypts and authenticates. Returns bytes written. Throws CryptographicException on tag mismatch.</summary>
    int Decrypt(ulong nonce, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext);
}
