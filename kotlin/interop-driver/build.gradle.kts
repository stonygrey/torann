// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
    application
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
    implementation(project(":torann"))
}

application {
    // interop/run.py runs the launcher that `installDist` writes to
    // build/install/interop-driver/bin/interop-driver, so the name is referenced there.
    mainClass.set("com.stonygrey.torann.interop.MainKt")
    applicationName = "interop-driver"
}
