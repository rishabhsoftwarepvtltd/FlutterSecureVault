#
# To learn more about a Podspec see http://guides.cocoapods.org/syntax/podspec.html.
# Run `pod lib lint rspl_secure_vault.podspec` to validate before publishing.
#
Pod::Spec.new do |s|
  s.name             = 'rspl_secure_vault'
  s.version          = '0.0.1'
  s.summary          = 'Secure encryption plugin using envelope encryption with iOS Secure Enclave/Keychain.'
  s.description      = <<-DESC
A Flutter plugin that provides secure encryption and decryption capabilities using envelope encryption.
Uses AES-GCM for data encryption, ECDH for key agreement, and leverages iOS Secure Enclave and Keychain
for hardware-backed key protection.
                       DESC
  s.homepage         = 'https://github.com/rishabhsoftwarepvtltd/rspl_secure_vault'
  s.license          = { :file => '../LICENSE' }
  s.author           = { 'RSPL' => 'contact@rspl.com' }
  s.source           = { :path => '.' }
  s.source_files = 'Classes/**/*'
  s.dependency 'Flutter'
  s.platform = :ios, '13.0'

  # Flutter.framework does not contain a i386 slice.
  s.pod_target_xcconfig = { 'DEFINES_MODULE' => 'YES', 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'i386' }
  s.swift_version = '5.0'

  # Privacy manifest for App Store compliance
  s.resource_bundles = {'rspl_secure_vault_privacy' => ['rspl_secure_vault/Sources/rspl_secure_vault/PrivacyInfo.xcprivacy']}
end
