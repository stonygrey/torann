// Copyright © 2026 Stony Grey LLC.
// SPDX-License-Identifier: MIT

/// The Dart API over the Pigeon host. The four types live in one library so that the
/// constructors that take a host handle stay private: application code cannot build an
/// alias of another component's host object from an integer.
library;

import 'dart:typed_data';

import 'host.dart';
import 'messages.g.dart';
import 'torann_exception.dart';

part 'handshake_state.dart';
part 'key_pair.dart';
part 'noise_protocol.dart';
part 'transport.dart';
