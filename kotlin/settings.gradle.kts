// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "torann-kotlin"

include(":torann", ":torann-testkit", ":android-tests", ":interop-driver")
