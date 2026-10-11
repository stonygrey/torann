// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

namespace Torann.Crypto;

internal interface IDhFunction
{
    string Name { get; }
    int DhLen { get; }
    void GeneratePrivateKey(Span<byte> privateKey);
    void DerivePublicKey(ReadOnlySpan<byte> privateKey, Span<byte> publicKey);
    void Dh(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> publicKey, Span<byte> sharedSecret);
}
