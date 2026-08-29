// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using Torann.Crypto;
using Xunit;

namespace Torann.Tests;

public class SecurityTests
{
    [Fact]
    public void TransportWriteAfterDisposeThrowsAndDoesNotEmitPlaintext()
    {
        var (init, resp) = CompleteNn();
        var secret = "secret!!"u8.ToArray();
        var message = new byte[64];
        message.AsSpan().Fill(0xAA);

        init.Dispose();
        Assert.Throws<ObjectDisposedException>(() => init.WriteMessage(secret, message));
        Assert.Equal(-1, message.AsSpan().IndexOf(secret));

        resp.Dispose();
    }

    [Fact]
    public void TransportReadAfterDisposeThrows()
    {
        var (init, resp) = CompleteNn();
        var message = new byte[64];
        var payload = new byte[64];
        var n = init.WriteMessage("hello"u8, message);
        resp.Dispose();
        Assert.Throws<ObjectDisposedException>(() => resp.ReadMessage(message.AsSpan(0, n), payload));
        init.Dispose();
    }

    [Fact]
    public void MidHandshakeDisposeThenWriteDoesNotEmitStaticKey()
    {
        var protocol = Protocol.Parse("Noise_XX_25519_ChaChaPoly_SHA256");
        using var initStatic = protocol.GenerateKeyPair();
        using var respStatic = protocol.GenerateKeyPair();
        var initiator = protocol.CreateHandshake(true, s: initStatic);
        var responder = protocol.CreateHandshake(false, s: respStatic);
        var message = new byte[1024];
        var payload = new byte[1024];
        message.AsSpan().Fill(0xAA);

        var (w1, _, _) = initiator.WriteMessage(default, message);
        responder.ReadMessage(message.AsSpan(0, w1), payload);
        var (w2, _, _) = responder.WriteMessage(default, message);
        initiator.ReadMessage(message.AsSpan(0, w2), payload);

        initiator.Dispose();
        message.AsSpan().Fill(0xAA);
        Assert.Throws<ObjectDisposedException>(() => initiator.WriteMessage(default, message));
        Assert.Equal(-1, message.AsSpan().IndexOf(initStatic.PublicKey));

        responder.Dispose();
    }

    [Fact]
    public void TamperedHandshakeReadIsTerminal()
    {
        var protocol = Protocol.Parse("Noise_XX_25519_ChaChaPoly_SHA256");
        using var initStatic = protocol.GenerateKeyPair();
        using var respStatic = protocol.GenerateKeyPair();
        using var initiator = protocol.CreateHandshake(true, s: initStatic);
        using var responder = protocol.CreateHandshake(false, s: respStatic);
        var message = new byte[1024];
        var payload = new byte[1024];

        var (w1, _, _) = initiator.WriteMessage(default, message);
        responder.ReadMessage(message.AsSpan(0, w1), payload);
        var (w2, _, _) = responder.WriteMessage(default, message);

        var good = message[..w2].ToArray();
        var tampered = (byte[])good.Clone();
        tampered[^1] ^= 0xFF;

        Assert.ThrowsAny<CryptographicException>(() => initiator.ReadMessage(tampered, payload));
        var retry = Assert.Throws<InvalidOperationException>(() => initiator.ReadMessage(good, payload));
        Assert.Contains("failed", retry.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Null(initiator.RemoteStaticPublicKey);
    }

    [Fact]
    public void OversizedHandshakePayloadDoesNotConsumeTheMessagePattern()
    {
        var protocol = Protocol.Parse("Noise_NN_25519_ChaChaPoly_SHA256");
        using var initiator = protocol.CreateHandshake(true);
        using var responder = protocol.CreateHandshake(false);
        var huge = new byte[70_000];
        var buffer = new byte[80_000];
        var payload = new byte[1024];

        Assert.Throws<ArgumentException>(() => initiator.WriteMessage(huge, buffer));

        var (written, _, _) = initiator.WriteMessage("hi"u8, buffer);
        var (read, _, _) = responder.ReadMessage(buffer.AsSpan(0, written), payload);
        Assert.Equal("hi"u8.ToArray(), payload[..read].ToArray());
    }

    [Fact]
    public void CreateHandshakeRejectsMissingStaticAndPsk()
    {
        var xx = Protocol.Parse("Noise_XX_25519_ChaChaPoly_SHA256");
        var missingStatic = Assert.Throws<ArgumentException>(() => xx.CreateHandshake(true));
        Assert.Contains("static", missingStatic.Message, StringComparison.OrdinalIgnoreCase);

        var xXpsk3 = Protocol.Parse("Noise_XXpsk3_25519_ChaChaPoly_SHA256");
        using var s = xXpsk3.GenerateKeyPair();
        var missingPsk = Assert.Throws<ArgumentException>(() => xXpsk3.CreateHandshake(true, s: s));
        Assert.Contains("pre-shared", missingPsk.Message, StringComparison.OrdinalIgnoreCase);

        var nk = Protocol.Parse("Noise_NK_25519_ChaChaPoly_SHA256");
        using var nkStatic = nk.GenerateKeyPair();
        var missingRemote = Assert.Throws<ArgumentException>(() => nk.CreateHandshake(true, s: nkStatic));
        Assert.Contains("remote", missingRemote.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ManagedChaChaPolyDisposeRejectsFurtherUse()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var aead = ChaChaPolyCipher.CreateKey(key, forceManaged: true);
        var plaintext = "abc"u8.ToArray();
        var ciphertext = new byte[plaintext.Length + 16];
        aead.Encrypt(0, default, plaintext, ciphertext);
        aead.Dispose();

        Assert.Throws<ObjectDisposedException>(() =>
            aead.Encrypt(1, default, plaintext, ciphertext));
        Assert.Throws<ObjectDisposedException>(() =>
        {
            var buffer = new byte[plaintext.Length];
            aead.Decrypt(0, default, ciphertext, buffer);
        });
    }

    [Fact]
    public void KeyPairPrivateKeyIsNotALiveWritableArray()
    {
        var protocol = Protocol.Parse("Noise_NN_25519_ChaChaPoly_SHA256");
        using var keys = protocol.GenerateKeyPair();
        var original = keys.PrivateKey[0];
        var copy = keys.PrivateKey.ToArray();
        copy[0] ^= 0xFF;
        Assert.Equal(original, keys.PrivateKey[0]);

        keys.Dispose();
        Assert.Throws<ObjectDisposedException>(() => _ = keys.PrivateKey.Length);
    }

    [Fact]
    public void RekeyRotatesTransportKeysWithoutResettingNonces()
    {
        var (init, resp) = CompleteNn();
        var message = new byte[128];
        var payload = new byte[128];

        var n1 = init.WriteMessage("one"u8, message);
        var first = message[..n1].ToArray();
        Assert.Equal(3, resp.ReadMessage(first, payload));

        init.RekeySend();
        var n2 = init.WriteMessage("two"u8, message);
        var second = message[..n2].ToArray();
        Assert.ThrowsAny<CryptographicException>(() => resp.ReadMessage(second, payload));

        resp.RekeyReceive();
        Assert.Equal("two"u8.ToArray(), payload[..resp.ReadMessage(second, payload)].ToArray());

        init.Dispose();
        resp.Dispose();
    }

    [Fact]
    public void SetReceiveNonceAllowsReplayOfAPreviousCiphertext()
    {
        var (init, resp) = CompleteNn();
        var message = new byte[128];
        var payload = new byte[128];
        var n = init.WriteMessage("ping"u8, message);
        var saved = message[..n].ToArray();
        resp.ReadMessage(saved, payload);

        resp.SetReceiveNonce(0);
        Assert.Equal("ping"u8.ToArray(), payload[..resp.ReadMessage(saved, payload)].ToArray());

        init.Dispose();
        resp.Dispose();
    }

    [Fact]
    public void RemoteStaticPublicKeyIsAvailableAfterSuccessfulXxMessage2()
    {
        var protocol = Protocol.Parse("Noise_XX_25519_ChaChaPoly_SHA256");
        using var initStatic = protocol.GenerateKeyPair();
        using var respStatic = protocol.GenerateKeyPair();
        using var initiator = protocol.CreateHandshake(true, s: initStatic);
        using var responder = protocol.CreateHandshake(false, s: respStatic);
        var message = new byte[1024];
        var payload = new byte[1024];

        var (w1, _, _) = initiator.WriteMessage(default, message);
        responder.ReadMessage(message.AsSpan(0, w1), payload);
        Assert.Null(initiator.RemoteStaticPublicKey);

        var (w2, _, _) = responder.WriteMessage(default, message);
        initiator.ReadMessage(message.AsSpan(0, w2), payload);
        Assert.Equal(respStatic.PublicKey, initiator.RemoteStaticPublicKey);
    }

    private static (Transport Init, Transport Resp) CompleteNn()
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
        return (initTransport!, respTransport!);
    }

    [Fact]
    public void OneWayTransportRejectsTheReverseDirection()
    {
        var protocol = Protocol.Parse("Noise_N_25519_AESGCM_SHA256");
        using var respStatic = protocol.GenerateKeyPair();

        using var initiator = protocol.CreateHandshake(
            initiator: true, remoteStatic: respStatic.PublicKey);
        using var responder = protocol.CreateHandshake(
            initiator: false, s: respStatic);

        var message = new byte[256];
        var payload = new byte[256];
        var (written, _, initTransport) = initiator.WriteMessage([], message);
        var (_, _, respTransport) = responder.ReadMessage(message.AsSpan(0, written), payload);

        Assert.NotNull(initTransport);
        Assert.NotNull(respTransport);

        // Initiator-to-responder works; the reverse direction must throw.
        var length = initTransport!.WriteMessage("one way"u8, message);
        Assert.Equal(7, respTransport!.ReadMessage(message.AsSpan(0, length), payload));

        Assert.Throws<InvalidOperationException>(() => respTransport.WriteMessage("nope"u8, message));
        Assert.Throws<InvalidOperationException>(() => initTransport.ReadMessage(message.AsSpan(0, length), payload));

        initTransport.Dispose();
        respTransport.Dispose();
    }

}
