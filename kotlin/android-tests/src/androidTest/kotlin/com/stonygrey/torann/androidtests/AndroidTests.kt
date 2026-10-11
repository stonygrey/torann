// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

package com.stonygrey.torann.androidtests

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.stonygrey.torann.testkit.SecurityTests
import com.stonygrey.torann.testkit.VectorSource
import com.stonygrey.torann.testkit.VectorTests
import org.junit.runner.RunWith

/** The vector files are assets of the test APK, read through the instrumentation context. */
class AssetVectorSource : VectorSource {
    override fun read(fileName: String): String =
        InstrumentationRegistry.getInstrumentation().context.assets.open(fileName).use { it.readBytes().toString(Charsets.UTF_8) }
}

@RunWith(AndroidJUnit4::class)
class AndroidVectorTests : VectorTests(AssetVectorSource())

@RunWith(AndroidJUnit4::class)
class AndroidSecurityTests : SecurityTests()
