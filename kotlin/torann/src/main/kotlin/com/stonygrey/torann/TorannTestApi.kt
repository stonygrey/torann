// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

/**
 * Marks the test-only entry points [HandshakeState.setFixedEphemeral] and
 * [TestCipherState]. They are public because `internal` is not visible from the
 * `torann-testkit` module; the ERROR level makes a call without
 * `@OptIn(TorannTestApi::class)` a compile error.
 */
@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = "This is a test-only Torann API. It is not part of the public API.",
)
@Retention(AnnotationRetention.BINARY)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION, AnnotationTarget.PROPERTY, AnnotationTarget.CONSTRUCTOR)
annotation class TorannTestApi
