// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Text.Json;
using System.Text.Json.Serialization;
using Xunit;
using Xunit.Abstractions;

namespace Torann.Tests;

/// <summary>
/// Runs every vector from the cacophony reference test suite whose protocol
/// Torann supports (NN/NK/KK/XX/IK ± psk, 25519, ChaChaPoly/AESGCM, SHA256/512).
/// Unsupported protocols (448, BLAKE2, one-way and deferred patterns) are skipped.
/// </summary>
public class CacophonyVectorTests(ITestOutputHelper output)
{
    [Fact]
    public void AllSupportedVectorsPass()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "Vectors", "cacophony.txt");
        var file = JsonSerializer.Deserialize<VectorFile>(File.ReadAllText(path))!;
        int run = 0, skipped = 0;

        foreach (var vector in file.Vectors)
        {
            Protocol protocol;
            try
            {
                protocol = Protocol.Parse(vector.ProtocolName!);
            }
            catch (NotSupportedException)
            {
                skipped++;
                continue;
            }

            try
            {
                RunVector(protocol, vector);
            }
            catch (Exception e)
            {
                Assert.Fail($"Vector '{vector.ProtocolName}' failed: {e}");
            }

            run++;
        }

        output.WriteLine($"Ran {run} vectors, skipped {skipped} unsupported.");
        Assert.True(run >= 40, $"Expected at least 40 supported vectors, ran {run}.");
    }

    private static void RunVector(Protocol protocol, Vector vector)
    {
        using var initStatic = CreateKeyPair(protocol, vector.InitStatic);
        using var respStatic = CreateKeyPair(protocol, vector.RespStatic);

        using var initiator = protocol.CreateHandshake(
            initiator: true,
            prologue: Hex(vector.InitPrologue),
            s: initStatic,
            remoteStatic: vector.InitRemoteStatic == null ? null : Hex(vector.InitRemoteStatic),
            psks: vector.InitPsks?.Select(p => Hex(p)!));
        initiator.FixedEphemeral = Hex(vector.InitEphemeral);

        using var responder = protocol.CreateHandshake(
            initiator: false,
            prologue: Hex(vector.RespPrologue),
            s: respStatic,
            remoteStatic: vector.RespRemoteStatic == null ? null : Hex(vector.RespRemoteStatic),
            psks: vector.RespPsks?.Select(p => Hex(p)!));
        responder.FixedEphemeral = Hex(vector.RespEphemeral);

        Transport? initTransport = null, respTransport = null;
        var messageBuffer = new byte[Protocol.MaxMessageLength + 64];
        var payloadBuffer = new byte[Protocol.MaxMessageLength];

        for (var i = 0; i < vector.Messages.Count; i++)
        {
            var message = vector.Messages[i];
            var payload = Hex(message.Payload)!;
            var expected = Hex(message.Ciphertext)!;
            var initiatorSends = i % 2 == 0;

            if (initTransport == null)
            {
                var writer = initiatorSends ? initiator : responder;
                var reader = initiatorSends ? responder : initiator;

                var (written, writerHash, writerTransport) = writer.WriteMessage(payload, messageBuffer);
                Assert.Equal(Convert.ToHexStringLower(expected), Convert.ToHexStringLower(messageBuffer.AsSpan(0, written)));

                var (read, readerHash, readerTransport) = reader.ReadMessage(messageBuffer.AsSpan(0, written), payloadBuffer);
                Assert.Equal(Convert.ToHexStringLower(payload), Convert.ToHexStringLower(payloadBuffer.AsSpan(0, read)));

                if (writerTransport != null)
                {
                    Assert.NotNull(readerTransport);
                    initTransport = initiatorSends ? writerTransport : readerTransport;
                    respTransport = initiatorSends ? readerTransport : writerTransport;

                    if (vector.HandshakeHash != null)
                    {
                        var expectedHash = Convert.ToHexStringLower(Hex(vector.HandshakeHash)!);
                        Assert.Equal(expectedHash, Convert.ToHexStringLower(writerHash!));
                        Assert.Equal(expectedHash, Convert.ToHexStringLower(readerHash!));
                    }
                }
            }
            else
            {
                var writer = initiatorSends ? initTransport : respTransport!;
                var reader = initiatorSends ? respTransport! : initTransport;

                var written = writer.WriteMessage(payload, messageBuffer);
                Assert.Equal(Convert.ToHexStringLower(expected), Convert.ToHexStringLower(messageBuffer.AsSpan(0, written)));

                var read = reader.ReadMessage(messageBuffer.AsSpan(0, written), payloadBuffer);
                Assert.Equal(Convert.ToHexStringLower(payload), Convert.ToHexStringLower(payloadBuffer.AsSpan(0, read)));
            }
        }

        initTransport?.Dispose();
        respTransport?.Dispose();
    }

    private static KeyPair? CreateKeyPair(Protocol protocol, string? privateKeyHex) =>
        privateKeyHex == null ? null : protocol.CreateKeyPair(Hex(privateKeyHex));

    private static byte[]? Hex(string? value) =>
        value == null ? null : Convert.FromHexString(value);

    private sealed class VectorFile
    {
        [JsonPropertyName("vectors")]
        public List<Vector> Vectors { get; set; } = [];
    }

    private sealed class Vector
    {
        [JsonPropertyName("protocol_name")]
        public string? ProtocolName { get; set; }

        [JsonPropertyName("init_prologue")]
        public string? InitPrologue { get; set; }

        [JsonPropertyName("init_psks")]
        public List<string>? InitPsks { get; set; }

        [JsonPropertyName("init_static")]
        public string? InitStatic { get; set; }

        [JsonPropertyName("init_ephemeral")]
        public string? InitEphemeral { get; set; }

        [JsonPropertyName("init_remote_static")]
        public string? InitRemoteStatic { get; set; }

        [JsonPropertyName("resp_prologue")]
        public string? RespPrologue { get; set; }

        [JsonPropertyName("resp_psks")]
        public List<string>? RespPsks { get; set; }

        [JsonPropertyName("resp_static")]
        public string? RespStatic { get; set; }

        [JsonPropertyName("resp_ephemeral")]
        public string? RespEphemeral { get; set; }

        [JsonPropertyName("resp_remote_static")]
        public string? RespRemoteStatic { get; set; }

        [JsonPropertyName("handshake_hash")]
        public string? HandshakeHash { get; set; }

        [JsonPropertyName("messages")]
        public List<Message> Messages { get; set; } = [];
    }

    private sealed class Message
    {
        [JsonPropertyName("payload")]
        public string? Payload { get; set; }

        [JsonPropertyName("ciphertext")]
        public string? Ciphertext { get; set; }
    }
}
