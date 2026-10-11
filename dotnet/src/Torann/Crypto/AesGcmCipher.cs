// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Torann.Crypto;

/// <summary>
/// AES-256-GCM per Noise §12.4: 12-byte nonce = 4 zero bytes || 64-bit
/// big-endian counter. OS-backed on every supported platform.
/// </summary>
internal sealed class AesGcmCipher : ICipherFunction
{
    public string Name => "AESGCM";

    public ICipherKey CreateKey(ReadOnlySpan<byte> key)
    {
        if (!AesGcm.IsSupported)
        {
            throw new PlatformNotSupportedException(
                "AES-GCM is not supported on this platform; prefer a ChaChaPoly protocol.");
        }

        return new Key(key);
    }

    private sealed class Key : ICipherKey
    {
        private readonly AesGcm _aead;
        private bool _disposed;

        internal Key(ReadOnlySpan<byte> key) => _aead = new AesGcm(key, tagSizeInBytes: 16);

        private static void WriteNonce(Span<byte> nonce, ulong n)
        {
            nonce[..4].Clear();
            BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], n);
        }

        public int Encrypt(ulong nonce, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Span<byte> n = stackalloc byte[12];
            WriteNonce(n, nonce);
            _aead.Encrypt(n, plaintext, ciphertext[..plaintext.Length], ciphertext.Slice(plaintext.Length, 16), ad);
            return plaintext.Length + 16;
        }

        public int Decrypt(ulong nonce, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Span<byte> n = stackalloc byte[12];
            WriteNonce(n, nonce);
            var length = ciphertext.Length - 16;
            _aead.Decrypt(n, ciphertext[..length], ciphertext[length..], plaintext[..length], ad);
            return length;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _aead.Dispose();
        }
    }
}
