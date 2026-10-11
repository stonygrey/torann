// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinVersion

import com.vanniktech.maven.publish.JavadocJar
import com.vanniktech.maven.publish.KotlinJvm

plugins {
    alias(libs.plugins.kotlin.jvm)
    `java-library`
    // Publishes through Maven Central's Central Portal, which Gradle's built-in
    // maven-publish plugin cannot upload to.
    alias(libs.plugins.maven.publish)
}

group = "com.stonygrey"
version = "0.3.1"

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}

mavenPublishing {
    publishToMavenCentral()
    // Signing is conditional so that local builds and publishToMavenLocal work without a
    // key. Maven Central rejects an unsigned upload.
    if (!providers.gradleProperty("signingInMemoryKey").orNull.isNullOrBlank()) {
        signAllPublications()
    }
    coordinates("com.stonygrey", "torann", version.toString())
    // Maven Central requires a javadoc jar; an empty one avoids a Dokka dependency.
    configure(KotlinJvm(javadocJar = JavadocJar.Empty(), sourcesJar = true))

    pom {
        name.set("Torann")
        description.set("The Noise Protocol Framework (revision 34) for Kotlin and Android: every handshake pattern with psk modifiers over 25519, 448, ChaChaPoly, AESGCM, SHA256, SHA512, BLAKE2s, and BLAKE2b.")
        inceptionYear.set("2026")
        url.set("https://github.com/stonygrey/torann")
        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/licenses/MIT")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("stonygrey")
                name.set("Stony Grey LLC")
                url.set("https://stonygrey.com")
            }
        }
        scm {
            url.set("https://github.com/stonygrey/torann")
            connection.set("scm:git:git://github.com/stonygrey/torann.git")
            developerConnection.set("scm:git:ssh://git@github.com/stonygrey/torann.git")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_11)
        // React Native 0.86 compiles its Android projects with Kotlin 2.1.20, and a Kotlin
        // compiler reads metadata at most one minor version newer than itself, so the jar
        // carries 2.1 metadata and depends on kotlin-stdlib 2.1.20.
        languageVersion.set(KotlinVersion.KOTLIN_2_1)
        apiVersion.set(KotlinVersion.KOTLIN_2_1)
    }
    coreLibrariesVersion = "2.1.20"
}

dependencies {
    // Supplies X25519, X448, BLAKE2s, and BLAKE2b.
    implementation(libs.bcprov)

    testImplementation(project(":torann-testkit"))
    testImplementation(libs.junit)
}

tasks.test {
    useJUnit()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
    }
}
