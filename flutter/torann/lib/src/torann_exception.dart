// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

/// The errors Torann raises. The six subclasses are the error categories every Torann
/// implementation shares. No message contains key material.
sealed class TorannException implements Exception {
  const TorannException(this.message);

  /// The message for logs.
  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

/// The name is not `Noise_` followed by four parts.
final class InvalidProtocolNameException extends TorannException {
  const InvalidProtocolNameException(super.message);
}

/// The pattern, modifier, DH, cipher, or hash is not supported on this platform.
final class UnsupportedFunctionException extends TorannException {
  const UnsupportedFunctionException(super.message);
}

/// A length, count, or required argument is wrong. The object remains usable.
final class InvalidArgumentException extends TorannException {
  const InvalidArgumentException(super.message);
}

/// Wrong turn, handshake complete or failed, one-way direction, or nonce exhausted.
final class InvalidStateException extends TorannException {
  const InvalidStateException(super.message);
}

/// A message is truncated or its tag does not verify. During a handshake this is
/// terminal once a message pattern has been consumed.
final class AuthenticationFailedException extends TorannException {
  const AuthenticationFailedException(super.message);
}

/// The object has been closed.
final class ClosedException extends TorannException {
  const ClosedException() : super('The object has been closed.');
}

/// The host failed outside the six Noise categories: the platform channel is gone,
/// the host threw something that is not a Torann error, or the message was malformed.
/// [code] is the Pigeon error code, such as `channel-error` or `hostFailure`.
final class HostFailureException extends TorannException {
  const HostFailureException(this.code, String message) : super(message);
  final String code;
}

/// Maps the error code the host sent over Pigeon back to the typed exception.
TorannException torannExceptionFromCode(String code, String? message) {
  final text = message ?? code;
  return switch (code) {
    'invalidProtocolName' => InvalidProtocolNameException(text),
    'unsupportedFunction' => UnsupportedFunctionException(text),
    'invalidArgument' => InvalidArgumentException(text),
    'invalidState' => InvalidStateException(text),
    'authenticationFailed' => AuthenticationFailedException(text),
    'closed' => const ClosedException(),
    _ => HostFailureException(code, text),
  };
}
