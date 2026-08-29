// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;
using Torann.Crypto;

namespace Torann;

/// <summary>
/// HandshakeState per Noise §5.3. Created via <see cref="Protocol.CreateHandshake"/>.
/// Call WriteMessage/ReadMessage alternately; the final message returns a
/// <see cref="Transport"/> for post-handshake traffic.
/// Any decrypt/DH error or exception after a message pattern is consumed is
/// terminal: the handshake must be discarded (Noise §5).
/// </summary>
public sealed class HandshakeState : IDisposable
{
    private readonly object _gate = new();
    private readonly SymmetricState _symmetric;
    private readonly IDhFunction _dh;
    private readonly bool _initiator;
    private readonly bool _oneWay;
    private readonly bool _hasPsk;
    private readonly Queue<Token[]> _messagePatterns;
    private readonly Queue<byte[]> _psks;
    private bool _turnToWrite;
    private bool _finished;
    private bool _failed;
    private bool _disposed;

    private byte[]? _sPrivate;
    private byte[]? _sPublic;
    private byte[]? _ePrivate;
    private byte[]? _ePublic;
    private byte[]? _rs;
    private byte[]? _re;

    // Test hook: cacophony vectors supply deterministic ephemerals.
    internal byte[]? FixedEphemeral;

    internal HandshakeState(
        Protocol protocol,
        bool initiator,
        ReadOnlySpan<byte> prologue,
        KeyPair? s,
        byte[]? remoteStatic,
        IEnumerable<byte[]>? psks)
    {
        _dh = protocol.Dh;
        _initiator = initiator;
        _oneWay = protocol.Pattern.Messages.Length == 1;
        _turnToWrite = initiator;
        _hasPsk = protocol.PskPositions.Count > 0;

        var pskList = (psks ?? []).Select(p =>
            p.Length == 32 ? (byte[])p.Clone() : throw new ArgumentException("Pre-shared keys must be 32 bytes.")).ToList();
        if (pskList.Count != protocol.PskPositions.Count)
        {
            throw new ArgumentException(
                $"The protocol requires {protocol.PskPositions.Count} pre-shared key(s); {pskList.Count} were provided.");
        }

        _psks = new Queue<byte[]>(pskList);

        var pattern = protocol.Pattern;
        var needsLocalStatic = initiator ? pattern.InitiatorSendsStatic : pattern.ResponderSendsStatic;
        var needsRemoteStatic = initiator ? pattern.HasResponderPreStatic : pattern.HasInitiatorPreStatic;

        if (needsLocalStatic && s == null)
        {
            throw new ArgumentException("A local static key is required by the handshake pattern.", nameof(s));
        }

        if (needsRemoteStatic && remoteStatic == null)
        {
            throw new ArgumentException(
                "The remote static public key is required by the handshake pattern.", nameof(remoteStatic));
        }

        if (s != null)
        {
            _sPrivate = s.PrivateKey.ToArray();
            _sPublic = (byte[])s.PublicKey.Clone();
        }

        if (remoteStatic != null)
        {
            if (remoteStatic.Length != _dh.DhLen)
            {
                throw new ArgumentException($"Remote static public key must be {_dh.DhLen} bytes.");
            }

            _rs = (byte[])remoteStatic.Clone();
        }

        _messagePatterns = new Queue<Token[]>(pattern.Messages);
        _symmetric = new SymmetricState(protocol.Name, protocol.Cipher, protocol.Hash);
        _symmetric.MixHash(prologue);

        foreach (var token in pattern.PreInitiator)
        {
            MixPreMessage(token, initiatorSide: true);
        }

        foreach (var token in pattern.PreResponder)
        {
            MixPreMessage(token, initiatorSide: false);
        }
    }

    /// <summary>
    /// The remote party's static public key, once known (e.g. after XX message 2).
    /// Null if the handshake has failed or the key is not yet available.
    /// </summary>
    public byte[]? RemoteStaticPublicKey
    {
        get
        {
            lock (_gate)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return _failed || _rs == null ? null : (byte[])_rs.Clone();
            }
        }
    }

    /// <summary>Writes the next handshake message (Noise §5.3 WriteMessage).</summary>
    /// <param name="payload">Optional application payload; encrypted once the handshake has derived a key.</param>
    /// <param name="messageBuffer">Receives the message. Must hold the pattern's key material plus payload and tag.</param>
    /// <returns>Bytes written; and, on the final message, the handshake hash and the <see cref="Transport"/> for application data.</returns>
    /// <exception cref="InvalidOperationException">It is not this party's turn, or the handshake has completed or failed.</exception>
    /// <exception cref="ArgumentException">The payload or buffer size is invalid; the handshake remains usable.</exception>
    public (int BytesWritten, byte[]? HandshakeHash, Transport? Transport) WriteMessage(
        ReadOnlySpan<byte> payload, Span<byte> messageBuffer)
    {
        lock (_gate)
        {
            ThrowIfUnavailable();
            if (!_turnToWrite)
            {
                throw new InvalidOperationException("It is not this party's turn to write a message.");
            }

            var tokens = _messagePatterns.Peek();
            var size = EstimateWriteLength(tokens, payload.Length);
            if (size > Protocol.MaxMessageLength)
            {
                throw new ArgumentException($"A Noise message must not exceed {Protocol.MaxMessageLength} bytes.");
            }

            if (messageBuffer.Length < size)
            {
                throw new ArgumentException("The message buffer is too small for the handshake message.", nameof(messageBuffer));
            }

            try
            {
                _messagePatterns.Dequeue();
                var offset = 0;
                foreach (var token in tokens)
                {
                    switch (token)
                    {
                        case Token.E:
                            _ePrivate = new byte[_dh.DhLen];
                            if (FixedEphemeral != null)
                            {
                                FixedEphemeral.CopyTo(_ePrivate, 0);
                            }
                            else
                            {
                                _dh.GeneratePrivateKey(_ePrivate);
                            }

                            _ePublic = new byte[_dh.DhLen];
                            _dh.DerivePublicKey(_ePrivate, _ePublic);
                            _ePublic.CopyTo(messageBuffer[offset..]);
                            offset += _dh.DhLen;
                            _symmetric.MixHash(_ePublic);
                            if (_hasPsk)
                            {
                                _symmetric.MixKey(_ePublic);
                            }

                            break;

                        case Token.S:
                            var sPublic = _sPublic ?? throw new InvalidOperationException("A local static key is required.");
                            offset += _symmetric.EncryptAndHash(sPublic, messageBuffer[offset..]);
                            break;

                        case Token.Psk:
                            MixPsk();
                            break;

                        default:
                            MixDh(token);
                            break;
                    }
                }

                offset += _symmetric.EncryptAndHash(payload, messageBuffer[offset..]);
                _turnToWrite = false;
                return Finish(offset);
            }
            catch
            {
                _failed = true;
                throw;
            }
        }
    }

    /// <summary>Reads the next handshake message from the peer (Noise §5.3 ReadMessage).</summary>
    /// <param name="message">The complete message as received.</param>
    /// <param name="payloadBuffer">Receives the decrypted payload.</param>
    /// <returns>Payload bytes written; and, on the final message, the handshake hash and the <see cref="Transport"/>.</returns>
    /// <exception cref="System.Security.Cryptography.CryptographicException">The message is truncated or fails authentication. The handshake is then failed and must be discarded.</exception>
    /// <exception cref="InvalidOperationException">It is not this party's turn, or the handshake has completed or failed.</exception>
    public (int BytesRead, byte[]? HandshakeHash, Transport? Transport) ReadMessage(
        ReadOnlySpan<byte> message, Span<byte> payloadBuffer)
    {
        lock (_gate)
        {
            ThrowIfUnavailable();
            if (_turnToWrite)
            {
                throw new InvalidOperationException("It is not this party's turn to read a message.");
            }

            if (message.Length > Protocol.MaxMessageLength)
            {
                throw new ArgumentException($"A Noise message must not exceed {Protocol.MaxMessageLength} bytes.");
            }

            var tokens = _messagePatterns.Peek();
            var (prefix, hasKey) = Simulate(tokens);
            var minLength = prefix + (hasKey ? Transport.TagSize : 0);
            if (message.Length < minLength)
            {
                throw new CryptographicException("The handshake message is truncated.");
            }

            var plaintextLength = hasKey
                ? message.Length - prefix - Transport.TagSize
                : message.Length - prefix;
            if (payloadBuffer.Length < plaintextLength)
            {
                throw new ArgumentException("The payload buffer is too small for the handshake payload.", nameof(payloadBuffer));
            }

            try
            {
                _messagePatterns.Dequeue();
                var rest = message;
                foreach (var token in tokens)
                {
                    switch (token)
                    {
                        case Token.E:
                            Require(rest.Length >= _dh.DhLen);
                            _re = rest[.._dh.DhLen].ToArray();
                            rest = rest[_dh.DhLen..];
                            _symmetric.MixHash(_re);
                            if (_hasPsk)
                            {
                                _symmetric.MixKey(_re);
                            }

                            break;

                        case Token.S:
                            var length = _dh.DhLen + (_symmetric.CipherHasKey ? 16 : 0);
                            Require(rest.Length >= length);
                            _rs = new byte[_dh.DhLen];
                            _symmetric.DecryptAndHash(rest[..length], _rs);
                            rest = rest[length..];
                            break;

                        case Token.Psk:
                            MixPsk();
                            break;

                        default:
                            MixDh(token);
                            break;
                    }
                }

                var payloadLength = _symmetric.DecryptAndHash(rest, payloadBuffer);
                _turnToWrite = true;
                return Finish(payloadLength);
            }
            catch
            {
                _failed = true;
                throw;
            }
        }
    }

    private (int, byte[]?, Transport?) Finish(int size)
    {
        if (_messagePatterns.Count > 0)
        {
            return (size, null, null);
        }

        _finished = true;
        var handshakeHash = _symmetric.GetHandshakeHash();
        var (c1, c2) = _symmetric.Split();
        ClearHandshakeSecrets();
        return (size, handshakeHash, new Transport(_initiator, c1, c2, _oneWay));
    }

    private void ClearHandshakeSecrets()
    {
        _symmetric.ClearSecrets();
        Zero(ref _sPrivate);
        Zero(ref _ePrivate);
        while (_psks.Count > 0)
        {
            CryptographicOperations.ZeroMemory(_psks.Dequeue());
        }
    }

    private int EstimateWriteLength(Token[] tokens, int payloadLength)
    {
        var (prefix, hasKey) = Simulate(tokens);
        var payloadOverhead = hasKey ? Transport.TagSize : 0;
        return prefix + payloadLength + payloadOverhead;
    }

    private (int Prefix, bool HasKey) Simulate(Token[] tokens)
    {
        var size = 0;
        var hasKey = _symmetric.CipherHasKey;
        foreach (var token in tokens)
        {
            switch (token)
            {
                case Token.E:
                    size += _dh.DhLen;
                    if (_hasPsk)
                    {
                        hasKey = true;
                    }

                    break;
                case Token.S:
                    size += _dh.DhLen + (hasKey ? Transport.TagSize : 0);
                    break;
                case Token.Psk:
                    hasKey = true;
                    break;
                default:
                    hasKey = true;
                    break;
            }
        }

        return (size, hasKey);
    }

    private void MixPreMessage(Token token, bool initiatorSide)
    {
        if (token != Token.S)
        {
            throw new NotSupportedException("Only 's' pre-message tokens are supported.");
        }

        var key = initiatorSide == _initiator ? _sPublic : _rs;
        _symmetric.MixHash(key ?? throw new InvalidOperationException(
            "A static key required by the handshake pattern's pre-messages is missing."));
    }

    private void MixPsk()
    {
        if (_psks.Count == 0)
        {
            throw new InvalidOperationException("The handshake pattern requires a pre-shared key that was not provided.");
        }

        var psk = _psks.Dequeue();
        _symmetric.MixKeyAndHash(psk);
        CryptographicOperations.ZeroMemory(psk);
    }

    private void MixDh(Token token)
    {
        var (privateKey, publicKey) = token switch
        {
            Token.Ee => (_ePrivate, _re),
            Token.Ss => (_sPrivate, _rs),
            Token.Es => _initiator ? (_ePrivate, _rs) : (_sPrivate, _re),
            Token.Se => _initiator ? (_sPrivate, _re) : (_ePrivate, _rs),
            _ => throw new InvalidOperationException($"Unexpected token {token}."),
        };

        if (privateKey == null || publicKey == null)
        {
            throw new InvalidOperationException($"Key material for the '{token}' token is missing.");
        }

        Span<byte> shared = stackalloc byte[_dh.DhLen];
        _dh.Dh(privateKey, publicKey, shared);
        _symmetric.MixKey(shared);
        CryptographicOperations.ZeroMemory(shared);
    }

    private static void Require(bool condition)
    {
        if (!condition)
        {
            throw new CryptographicException("The handshake message is truncated.");
        }
    }

    private void ThrowIfUnavailable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_failed)
        {
            throw new InvalidOperationException("The handshake has failed and must be discarded.");
        }

        if (_finished)
        {
            throw new InvalidOperationException("The handshake is already complete.");
        }
    }

    /// <summary>Zeros all key material. The handshake cannot be used afterwards.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _failed = true;
            _symmetric.Dispose();
            Zero(ref _sPrivate);
            Zero(ref _ePrivate);
            while (_psks.Count > 0)
            {
                CryptographicOperations.ZeroMemory(_psks.Dequeue());
            }
        }
    }

    private static void Zero(ref byte[]? key)
    {
        if (key != null)
        {
            CryptographicOperations.ZeroMemory(key);
            key = null;
        }
    }
}
