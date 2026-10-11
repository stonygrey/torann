// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using Torann.Crypto;
using Xunit;

namespace Torann.Tests;

public class CryptoTests
{
    [Fact]
    public void RekeyMatchesTheSpecDefinition()
    {
        // No reference suite carries rekey vectors, so this test computes the spec's
        // definition REKEY(k) = ENCRYPT(k, 2^64-1, empty, zeros[32])[..32] directly, with
        // the nonce preserved; a deviation shared by both sides of a session would pass
        // the round-trip tests otherwise.
        foreach (ICipherFunction cipher in new ICipherFunction[] { new AesGcmCipher(), new ChaChaPolyCipher() })
        {
            var key = RandomNumberGenerator.GetBytes(32);

            using var direct = cipher.CreateKey(key);
            var rekeyed = new byte[48];
            direct.Encrypt(ulong.MaxValue, default, new byte[32], rekeyed);

            using var expectedKey = cipher.CreateKey(rekeyed.AsSpan(0, 32).ToArray());
            var expected = new byte[10 + 16];
            expectedKey.Encrypt(5, default, "handshake!"u8, expected);

            using var state = new CipherState(cipher);
            state.InitializeKey(key);
            state.SetNonce(5);
            state.Rekey();
            var actual = new byte[10 + 16];
            state.EncryptWithAd(default, "handshake!"u8, actual);

            Assert.Equal(expected, actual);
        }
    }

    [Fact]
    public void ManagedChaChaPolyInteroperatesWithPlatformImplementation()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var ad = RandomNumberGenerator.GetBytes(24);
        var plaintext = RandomNumberGenerator.GetBytes(347);

        using var platform = ChaChaPolyCipher.CreateKey(key, forceManaged: false);
        using var managed = ChaChaPolyCipher.CreateKey(key, forceManaged: true);

        var ciphertext1 = new byte[plaintext.Length + 16];
        var ciphertext2 = new byte[plaintext.Length + 16];
        platform.Encrypt(7, ad, plaintext, ciphertext1);
        managed.Encrypt(7, ad, plaintext, ciphertext2);
        Assert.Equal(ciphertext1, ciphertext2);

        var decrypted = new byte[plaintext.Length];
        managed.Decrypt(7, ad, ciphertext1, decrypted);
        Assert.Equal(plaintext, decrypted);

        ciphertext1[3] ^= 0x01;
        Assert.ThrowsAny<CryptographicException>(() =>
        {
            var buffer = new byte[plaintext.Length];
            managed.Decrypt(7, ad, ciphertext1, buffer);
        });
    }

    [Fact]
    public void RoundTripWithRandomKeysAcrossSupportedProtocols()
    {
        string[] names =
        [
            "Noise_NN_25519_ChaChaPoly_SHA256",
            "Noise_XX_25519_ChaChaPoly_SHA256",
            "Noise_IK_25519_AESGCM_SHA512",
            "Noise_KK_25519_ChaChaPoly_SHA512",
            "Noise_NK_25519_AESGCM_SHA256",
            "Noise_XXpsk3_25519_ChaChaPoly_SHA256",
        ];

        foreach (var name in names)
        {
            var protocol = NoiseProtocol.Parse(name);
            using var initStatic = protocol.GenerateKeyPair();
            using var respStatic = protocol.GenerateKeyPair();
            var psk = protocol.PskPositions.Count > 0 ? new[] { RandomNumberGenerator.GetBytes(32) } : null;
            var needsRemote = name.Contains("_NK") || name.Contains("_KK") || name.Contains("_IK");

            using var initiator = protocol.CreateHandshake(
                true, "torann"u8, initStatic, needsRemote ? respStatic.PublicKey : null, psk);
            using var responder = protocol.CreateHandshake(
                false, "torann"u8, respStatic, name.Contains("_KK") ? initStatic.PublicKey : null, psk);

            var message = new byte[NoiseProtocol.MaxMessageLength];
            var payload = new byte[NoiseProtocol.MaxMessageLength];
            Transport? initTransport = null, respTransport = null;

            var writer = initiator;
            var reader = responder;
            while (initTransport == null)
            {
                var (written, _, wt) = writer.WriteMessage("ping"u8, message);
                var (read, _, rt) = reader.ReadMessage(message.AsSpan(0, written), payload);
                Assert.Equal("ping"u8.ToArray(), payload[..read]);
                if (wt != null)
                {
                    initTransport = writer == initiator ? wt : rt;
                    respTransport = writer == initiator ? rt : wt;
                }

                (writer, reader) = (reader, writer);
            }

            var data = RandomNumberGenerator.GetBytes(1024);
            var n = initTransport.WriteMessage(data, message);
            var m = respTransport!.ReadMessage(message.AsSpan(0, n), payload);
            Assert.Equal(data, payload[..m]);

            n = respTransport.WriteMessage(data, message);
            m = initTransport.ReadMessage(message.AsSpan(0, n), payload);
            Assert.Equal(data, payload[..m]);

            initTransport.Dispose();
            respTransport.Dispose();
        }
    }

    [Fact]
    public void TamperedTransportMessageThrows()
    {
        var protocol = NoiseProtocol.Parse("Noise_NN_25519_ChaChaPoly_SHA256");
        using var initiator = protocol.CreateHandshake(true);
        using var responder = protocol.CreateHandshake(false);

        var message = new byte[1024];
        var payload = new byte[1024];
        var (w1, _, _) = initiator.WriteMessage(default, message);
        responder.ReadMessage(message.AsSpan(0, w1), payload);
        var (w2, _, respTransport) = responder.WriteMessage(default, message);
        var (_, _, initTransport) = initiator.ReadMessage(message.AsSpan(0, w2), payload);

        var n = initTransport!.WriteMessage("secret"u8, message);
        message[2] ^= 0xFF;
        Assert.ThrowsAny<CryptographicException>(() => respTransport!.ReadMessage(message.AsSpan(0, n), payload));

        initTransport.Dispose();
        respTransport!.Dispose();
    }
}
