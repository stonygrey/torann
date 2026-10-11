# Copyright © 2026 Stony Grey LLC.
# SPDX-License-Identifier: MIT
#
# The sources under Torann/ are copies written by lib/sync-reactnative-sources.
Pod::Spec.new do |s|
  s.name           = 'Torann'
  s.version        = '0.3.1'
  s.summary        = 'The Noise Protocol Framework for React Native (Swift and Kotlin implementations).'
  s.description    = 'Torann implements the Noise Protocol Framework (revision 34). On iOS this pod compiles the Swift implementation, built on CryptoKit.'
  s.author         = { 'Stony Grey LLC' => 'hello@stonygrey.com' }
  s.homepage       = 'https://github.com/stonygrey/torann'
  s.license        = { :type => 'MIT', :file => '../LICENSE' }
  s.platforms      = { :ios => '18.0' }
  s.source         = { git: 'https://github.com/stonygrey/torann.git', tag: "v#{s.version}" }
  s.static_framework = true
  s.swift_version  = '5.9'

  s.dependency 'ExpoModulesCore'

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
  }

  s.source_files = "**/*.{h,m,mm,swift,hpp,cpp}"
end
