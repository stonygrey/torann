// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

/** The six Torann error categories, plus `hostFailure` for anything that is not a Torann error. */
export type TorannErrorCode =
  | 'invalidProtocolName'
  | 'unsupportedFunction'
  | 'invalidArgument'
  | 'invalidState'
  | 'authenticationFailed'
  | 'closed'
  | 'hostFailure';

const codes: ReadonlySet<string> = new Set([
  'invalidProtocolName',
  'unsupportedFunction',
  'invalidArgument',
  'invalidState',
  'authenticationFailed',
  'closed',
]);

/**
 * The error Torann throws. `code` is what an application branches on; `message` is
 * for logs and never contains key material. `hostFailure` means the native side
 * failed outside the six categories, and the message then carries only the native
 * exception's type name.
 */
export class TorannError extends Error {
  constructor(
    readonly code: TorannErrorCode,
    message: string
  ) {
    super(message);
    this.name = 'TorannError';
  }
}

const causeMarker = '→ Caused by: ';

/**
 * Expo wraps an exception thrown by a native function in a `FunctionCallException`
 * whose message is the wrapper's own text, a line break, `→ Caused by: `, and the host
 * exception's message, on both platforms. The host message is the part after the last
 * marker; a message without the marker is used whole.
 */
function hostMessage(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  const index = message.lastIndexOf(causeMarker);
  return index < 0 ? message : message.slice(index + causeMarker.length);
}

export function nativeCall<T>(fn: () => T): T {
  try {
    return fn();
  } catch (error) {
    if (error instanceof TorannError) {
      throw error;
    }
    const code = (error as { code?: unknown })?.code;
    const message = hostMessage(error);
    if (typeof code === 'string' && codes.has(code)) {
      throw new TorannError(code as TorannErrorCode, message);
    }
    throw new TorannError(
      'hostFailure',
      typeof code === 'string' ? `${code}: ${message}` : message
    );
  }
}
