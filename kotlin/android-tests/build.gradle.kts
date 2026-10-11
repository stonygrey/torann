// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.stonygrey.torann.androidtests"
    compileSdk = 36

    defaultConfig {
        minSdk = 33
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    packaging {
        resources.excludes += setOf("META-INF/versions/9/OSGI-INF/MANIFEST.MF")
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
    }
}

// `extensions.configure` with the `com.android.build.api.dsl` interface is the form
// that both AGP 8 and AGP 9 accept.
extensions.configure<com.android.build.api.dsl.LibraryExtension>("android") {
    sourceSets.named("androidTest") {
        assets.srcDirs(rootProject.file("../vectors"))
    }
}

dependencies {
    androidTestImplementation(project(":torann-testkit"))
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.ext.junit)
}
