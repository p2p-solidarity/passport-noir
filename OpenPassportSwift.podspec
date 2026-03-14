Pod::Spec.new do |spec|
  spec.name = "OpenPassportSwift"
  spec.version = "0.1.0"
  spec.summary = "iOS Swift bindings for OpenPassport Noir circuits via mopro."
  spec.description = <<-DESC
Provides an iOS-only Swift SDK wrapping generated mopro bindings for Noir-based OpenPassport proof generation and verification.
DESC

  spec.homepage = "https://github.com/kidneyweakx/conductor-playground"
  spec.license = { :type => "Apache-2.0" }
  spec.author = { "OpenPassportSwift" => "hello@zkmopro.org" }

  spec.platform = :ios, "15.0"
  spec.swift_versions = ["5.10"]

  spec.source = {
    :git => "https://github.com/kidneyweakx/conductor-playground.git",
    :tag => "v#{spec.version}"
  }

  spec.source_files = "Sources/**/*.swift"
  spec.vendored_frameworks = "Sources/MoproiOSBindings/MoproBindings.xcframework"
end
