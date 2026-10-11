// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// The C# interop driver. It reads one command per line from stdin and writes one
// response line per command, following the protocol in interop/README.md.

using System.Security.Cryptography;
using Torann;

var session = new Session();
string? line;
while ((line = Console.ReadLine()) != null)
{
    var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
    if (parts.Length == 0)
    {
        continue;
    }

    if (parts[0] == "quit")
    {
        Console.WriteLine("ok");
        break;
    }

    try
    {
        Console.WriteLine(session.Execute(parts));
    }
    catch (Exception e)
    {
        Console.WriteLine($"error {Session.Category(e)} {e.Message.Replace('\n', ' ')}");
    }
}

sealed class Session
{
    private NoiseProtocol? _protocol;
    private HandshakeState? _handshake;
    private Transport? _transport;
    private byte[]? _handshakeHash;

    public string Execute(string[] parts)
    {
        switch (parts[0])
        {
            case "keygen":
            {
                var protocol = NoiseProtocol.Parse(parts[1]);
                using var keys = protocol.GenerateKeyPair();
                return $"ok {Hex(keys.PrivateKey.ToArray())} {Hex(keys.PublicKey)}";
            }
            case "init":
            {
                Reset();
                _protocol = NoiseProtocol.Parse(parts[1]);
                var initiator = parts[2] == "initiator";
                using var local = parts[4] == "-" ? null : _protocol.CreateKeyPair(Unhex(parts[4]));
                var remote = parts[5] == "-" ? null : Unhex(parts[5]);
                var psks = parts[6] == "-" ? null : parts[6].Split(',').Select(Unhex).ToList();
                _handshake = _protocol.CreateHandshake(initiator, Unhex(parts[3]), local, remote, psks);
                return "ok";
            }
            case "write":
            {
                var payload = Unhex(parts[1]);
                var buffer = new byte[NoiseProtocol.MaxMessageLength];
                if (_transport != null)
                {
                    var n = _transport.WriteMessage(payload, buffer);
                    return $"ok {Hex(buffer.AsSpan(0, n).ToArray())}";
                }

                var (written, hash, transport) = Handshake.WriteMessage(payload, buffer);
                var message = Hex(buffer.AsSpan(0, written).ToArray());
                return Complete(hash, transport) ? $"ok {message} done {Hex(_handshakeHash!)}" : $"ok {message}";
            }
            case "read":
            {
                var message = Unhex(parts[1]);
                var buffer = new byte[NoiseProtocol.MaxMessageLength];
                if (_transport != null)
                {
                    var n = _transport.ReadMessage(message, buffer);
                    return $"ok {Hex(buffer.AsSpan(0, n).ToArray())}";
                }

                var (read, hash, transport) = Handshake.ReadMessage(message, buffer);
                var payload = Hex(buffer.AsSpan(0, read).ToArray());
                return Complete(hash, transport) ? $"ok {payload} done {Hex(_handshakeHash!)}" : $"ok {payload}";
            }
            case "rekey":
                if (parts[1] == "send") TransportOrThrow.RekeySend(); else TransportOrThrow.RekeyReceive();
                return "ok";
            case "hash":
                return _handshakeHash == null
                    ? throw new InvalidOperationException("The handshake is not complete.")
                    : $"ok {Hex(_handshakeHash)}";
            case "remote-static":
                return $"ok {Hex(Handshake.RemoteStaticPublicKey)}";
            default:
                throw new ArgumentException($"Unknown command '{parts[0]}'.");
        }
    }

    private HandshakeState Handshake => _handshake ?? throw new InvalidOperationException("No session; send init first.");

    private Transport TransportOrThrow => _transport ?? throw new InvalidOperationException("The handshake is not complete.");

    private bool Complete(byte[]? hash, Transport? transport)
    {
        if (transport == null)
        {
            return false;
        }

        _transport = transport;
        _handshakeHash = hash;
        return true;
    }

    private void Reset()
    {
        _handshake?.Dispose();
        _transport?.Dispose();
        _handshake = null;
        _transport = null;
        _handshakeHash = null;
    }

    public static string Category(Exception e) => e switch
    {
        ObjectDisposedException => "closed",
        NotSupportedException => "unsupportedFunction",
        ArgumentException a when a.Message.Contains("not a valid Noise protocol name") => "invalidProtocolName",
        ArgumentException => "invalidArgument",
        InvalidOperationException => "invalidState",
        CryptographicException => "authenticationFailed",
        _ => "invalidState",
    };

    private static string Hex(byte[]? bytes) => bytes == null || bytes.Length == 0 ? "-" : Convert.ToHexStringLower(bytes);

    private static byte[] Unhex(string hex) => hex == "-" ? [] : Convert.FromHexString(hex);
}
