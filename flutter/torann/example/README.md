<!-- Copyright © 2026 Stony Grey LLC. SPDX-License-Identifier: MIT -->

# Torann Flutter example

This app is the device test for the Torann Flutter plugin. It has no user interface of its own beyond the Flutter template. Its purpose is `integration_test/torann_test.dart`, which runs on a device or simulator and exercises the plugin against the native code it wraps.

The integration test runs the shared Noise test vectors through the plugin, 440 on iOS and all 1,352 on Android, from the copies under `assets/vectors` that `lib/sync-flutter-sources` writes. It then runs handshakes with freshly generated keys through the public API, checks that rekey and tampering behave as specified, checks the key derivation examples of RFC 7748 §6, and checks that the platform rejects or accepts the `448` and `BLAKE2` functions by name.

Run it with `flutter test integration_test -d <device>` from this folder. On Android the app resolves `com.stonygrey:torann` from the local Maven repository, so `cd kotlin && ./gradlew :torann:publishToMavenLocal` must have been run first. The app's identifiers are `com.example.torann_example` on Android and `com.example.torannExample` on iOS, which are placeholders in the form `flutter create` produces.
