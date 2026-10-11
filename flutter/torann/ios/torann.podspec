Pod::Spec.new do |s|
  s.name             = 'torann'
  s.version          = '0.3.0'
  s.summary          = 'The Noise Protocol Framework for Flutter (Swift and Kotlin implementations).'
  s.description      = <<-DESC
Torann implements the Noise Protocol Framework (revision 34). On iOS the plugin
compiles the Swift implementation, built on CryptoKit, into this pod.
                       DESC
  s.homepage         = 'https://github.com/stonygrey/torann'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'Stony Grey LLC' => 'hello@stonygrey.com' }
  s.source           = { :path => '.' }
  s.source_files = 'torann/Sources/torann/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '18.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.9'
end
