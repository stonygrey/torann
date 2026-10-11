// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// `expo prebuild` regenerates android/, so mavenLocal() is inserted into the generated
// android/build.gradle by this plugin rather than edited in. The example needs it until
// com.stonygrey:torann is on Maven Central.
const { withProjectBuildGradle } = require('expo/config-plugins');

module.exports = function withMavenLocal(config) {
  return withProjectBuildGradle(config, (c) => {
    const contents = c.modResults.contents;
    if (c.modResults.language === 'groovy' && !contents.includes('mavenLocal()')) {
      c.modResults.contents = contents.replace(
        /allprojects\s*\{\s*repositories\s*\{/,
        (match) => `${match}\n    mavenLocal()`
      );
    }
    return c;
  });
};
