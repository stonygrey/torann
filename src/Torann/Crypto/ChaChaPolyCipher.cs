// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using BcChaCha20Poly1305 = Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305;

namespace Torann.Crypto;

/// <summary>
/// ChaCha20-Poly1305 per Noise §12.3: 12-byte nonce = 4 zero bytes || 64-bit
/// little-endian counter. Uses the OS-backed BCL implementation where available
/// (CryptoKit on Apple platforms from .NET 9, OpenSSL/Conscrypt elsewhere) and
/// falls back to Bouncy Castle's managed implementation (e.g. Android API &lt; 28).
/// </summary>
internal sealed class ChaChaPolyCipher : ICipherFunction
{
    public string Name => "ChaChaPoly";

    public ICipherKey CreateKey(ReadOnlySpan<byte> key) => CreateKey(key, forceManaged: false);

    internal static ICipherKey CreateKey(ReadOnlySpan<byte> key, bool forceManaged) =>
        !forceManaged && ChaCha20Poly1305.IsSupported ? new BclKey(key) : new ManagedKey(key);

    private static void WriteNonce(Span<byte> nonce, ulong n)
    {
        nonce[..4].Clear();
        BinaryPrimitives.WriteUInt64LittleEndian(nonce[4..], n);
    }

    private sealed class BclKey : ICipherKey
    {
        private readonly ChaCha20Poly1305 _aead;
        private bool _disposed;

        internal BclKey(ReadOnlySpan<byte> key) => _aead = new ChaCha20Poly1305(key);

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

    private sealed class ManagedKey : ICipherKey
    {
        private KeyParameter? _key;
        private bool _disposed;

        internal ManagedKey(ReadOnlySpan<byte> key) => _key = new KeyParameter(key.ToArray());

        public int Encrypt(ulong nonce, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var cipher = Create(forEncryption: true, nonce, ad);
            var input = plaintext.ToArray();
            var output = new byte[input.Length + 16];
            var length = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            length += cipher.DoFinal(output, length);
            output.AsSpan(0, length).CopyTo(ciphertext);
            CryptographicOperations.ZeroMemory(input);
            return length;
        }

        public int Decrypt(ulong nonce, ReadOnlySpan<byte> ad, ReadOnlySpan<byte> ciphertext, Span<byte> plaintext)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var cipher = Create(forEncryption: false, nonce, ad);
            var input = ciphertext.ToArray();
            var output = new byte[input.Length - 16];
            try
            {
                var length = cipher.ProcessBytes(input, 0, input.Length, output, 0);
                length += cipher.DoFinal(output, length);
                output.AsSpan(0, length).CopyTo(plaintext);
                return length;
            }
            catch (Org.BouncyCastle.Crypto.InvalidCipherTextException e)
            {
                throw new AuthenticationTagMismatchException(e.Message);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(output);
            }
        }

        private BcChaCha20Poly1305 Create(bool forEncryption, ulong nonce, ReadOnlySpan<byte> ad)
        {
            var n = new byte[12];
            WriteNonce(n, nonce);
            var cipher = new BcChaCha20Poly1305();
            cipher.Init(forEncryption, new AeadParameters(_key!, 128, n));
            if (!ad.IsEmpty)
            {
                var adArray = ad.ToArray();
                cipher.ProcessAadBytes(adArray, 0, adArray.Length);
            }

            return cipher;
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            // KeyParameter.GetKey() and its constructor both clone; there is no
            // public BC API that exposes the internal key bytes to zero. The
            // managed-fallback key is therefore GC-lifetime, like every other
            // KeyParameter holder.
            _key = null;
        }
    }
}
