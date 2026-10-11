// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

import java.util.Arrays

/** Overwrites the array with zeros. Copies the JVM made elsewhere are not reached. */
internal fun ByteArray.wipe() {
    Arrays.fill(this, 0)
}
