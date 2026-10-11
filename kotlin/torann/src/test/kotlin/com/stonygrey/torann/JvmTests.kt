// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann

import com.stonygrey.torann.testkit.FileVectorSource
import com.stonygrey.torann.testkit.SecurityTests
import com.stonygrey.torann.testkit.VectorTests
import java.io.File

/** Gradle runs tests with the module directory as the working directory, so `../../vectors` is the shared folder. */
class JvmVectorTests : VectorTests(FileVectorSource(File("../../vectors")))

class JvmSecurityTests : SecurityTests()
