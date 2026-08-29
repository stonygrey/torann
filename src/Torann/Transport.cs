// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

namespace Torann;

/// <summary>
/// Post-handshake transport state: one send and one receive CipherState
/// (Noise §5). Messages carry a 16-byte authentication tag.
/// Not safe for concurrent use from multiple threads without the internal lock
/// around each public method; do not hold a call across awaits.
/// </summary>
public sealed class Transport : IDisposable
{
    /// <summary>Size in bytes of the AEAD authentication tag appended to every transport message.</summary>
    public const int TagSize = 16;

    private readonly object _gate = new();
    private readonly CipherState? _send;
    private readonly CipherState? _receive;
    private bool _disposed;

    internal Transport(bool initiator, CipherState c1, CipherState c2, bool oneWay = false)
    {
        if (oneWay)
        {
            // One-way patterns (Noise §7.4) use only the first CipherState;
            // traffic flows initiator-to-responder only.
            _send = initiator ? c1 : null;
            _receive = initiator ? null : c1;
            c2.Dispose();
        }
        else
        {
            _send = initiator ? c1 : c2;
            _receive = initiator ? c2 : c1;
        }
    }

    private CipherState Send => _send
        ?? throw new InvalidOperationException("A one-way pattern's responder cannot send transport messages.");

    private CipherState Receive => _receive
        ?? throw new InvalidOperationException("A one-way pattern's initiator cannot receive transport messages.");

    /// <summary>Encrypts payload into messageBuffer. Returns bytes written (payload length + 16).</summary>
    public int WriteMessage(ReadOnlySpan<byte> payload, Span<byte> messageBuffer)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (payload.Length > Protocol.MaxMessageLength - TagSize)
            {
                throw new ArgumentException($"The payload must not exceed {Protocol.MaxMessageLength - TagSize} bytes.");
            }

            if (messageBuffer.Length < payload.Length + TagSize)
            {
                throw new ArgumentException("The message buffer is too small for the ciphertext.", nameof(messageBuffer));
            }

            return Send.EncryptWithAd(default, payload, messageBuffer);
        }
    }

    /// <summary>Decrypts and authenticates message into payloadBuffer. Returns bytes written.</summary>
    public int ReadMessage(ReadOnlySpan<byte> message, Span<byte> payloadBuffer)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (message.Length > Protocol.MaxMessageLength)
            {
                throw new ArgumentException($"A Noise message must not exceed {Protocol.MaxMessageLength} bytes.");
            }

            var plaintextLength = message.Length >= TagSize ? message.Length - TagSize : 0;
            if (payloadBuffer.Length < plaintextLength)
            {
                throw new ArgumentException("The payload buffer is too small for the plaintext.", nameof(payloadBuffer));
            }

            return Receive.DecryptWithAd(default, message, payloadBuffer);
        }
    }

    /// <summary>Rekeys the outgoing CipherState (Noise §11.3). Does not reset the nonce.</summary>
    public void RekeySend()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Send.Rekey();
        }
    }

    /// <summary>Rekeys the incoming CipherState (Noise §11.3). Does not reset the nonce.</summary>
    public void RekeyReceive()
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Receive.Rekey();
        }
    }

    /// <summary>Sets the outgoing nonce. For out-of-order transport (Noise §11.4) only.</summary>
    public void SetSendNonce(ulong nonce)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Send.SetNonce(nonce);
        }
    }

    /// <summary>Sets the incoming nonce. For out-of-order transport (Noise §11.4) only.</summary>
    public void SetReceiveNonce(ulong nonce)
    {
        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            Receive.SetNonce(nonce);
        }
    }

    /// <summary>Disposes both cipher states and zeros their keys. Further calls throw <see cref="ObjectDisposedException"/>.</summary>
    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _send?.Dispose();
            _receive?.Dispose();
        }
    }
}
