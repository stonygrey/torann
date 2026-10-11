// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT
//
// The parent folder's react and react-native are blocked because npm installs them there
// for the package's peer dependencies, and a second copy of React in the bundle fails at
// runtime.
const { getDefaultConfig } = require('expo/metro-config');
const path = require('path');

const config = getDefaultConfig(__dirname);

config.resolver.blockList = [
  ...Array.from(config.resolver.blockList ?? []),
  new RegExp(path.resolve('..', 'node_modules', 'react').replace(/\\/g, '\\\\')),
  new RegExp(path.resolve('..', 'node_modules', 'react-native').replace(/\\/g, '\\\\')),
];

config.resolver.nodeModulesPaths = [
  path.resolve(__dirname, './node_modules'),
  path.resolve(__dirname, '../node_modules'),
];

config.resolver.extraNodeModules = {
  '@stonygrey/torann': '..',
};

config.watchFolders = [path.resolve(__dirname, '..')];

module.exports = config;
