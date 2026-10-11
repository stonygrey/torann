// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
    }
}

dependencies {
    // `api`, because :torann and :android-tests extend the test classes. JUnit 4 is the
    // framework AndroidJUnitRunner runs.
    api(project(":torann"))
    api(libs.junit)
}
