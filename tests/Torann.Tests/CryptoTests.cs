// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using Torann.Crypto;
using Xunit;

namespace Torann.Tests;

public class CryptoTests
{
    [Fact]
    public void X25519MatchesRfc7748Vector()
    {
        var scalar = Convert.FromHexString("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        var point = Convert.FromHexString("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        var expected = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";

        var dh = new Curve25519Dh();
        var shared = new byte[32];
        dh.Dh(scalar, point, shared);

        Assert.Equal(expected, Convert.ToHexStringLower(shared));
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
            var protocol = Protocol.Parse(name);
            using var initStatic = protocol.GenerateKeyPair();
            using var respStatic = protocol.GenerateKeyPair();
            var psk = protocol.PskPositions.Count > 0 ? new[] { RandomNumberGenerator.GetBytes(32) } : null;
            var needsRemote = name.Contains("_NK") || name.Contains("_KK") || name.Contains("_IK");

            using var initiator = protocol.CreateHandshake(
                true, "torann"u8, initStatic, needsRemote ? respStatic.PublicKey : null, psk);
            using var responder = protocol.CreateHandshake(
                false, "torann"u8, respStatic, name.Contains("_KK") ? initStatic.PublicKey : null, psk);

            var message = new byte[Protocol.MaxMessageLength];
            var payload = new byte[Protocol.MaxMessageLength];
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
        var protocol = Protocol.Parse("Noise_NN_25519_ChaChaPoly_SHA256");
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
