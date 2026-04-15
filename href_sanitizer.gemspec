# frozen_string_literal: true

require_relative "lib/href_sanitizer/version"

Gem::Specification.new do |spec|
  spec.name = "href_sanitizer"
  spec.version = HrefSanitizer::VERSION
  spec.authors = ["mfo"]
  spec.summary = "Harden Rails security defaults: safe link_to, SSRF-proof URL validation"
  spec.description = "Drop-in Rails engine that patches link_to to block dangerous protocols (javascript:, data:, vbscript:) " \
                     "and provides a URL validator to prevent SSRF via private/local IP resolution."
  spec.homepage = "https://github.com/mfo/href_sanitizer"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1"

  spec.files = Dir["lib/**/*", "LICENSE.txt", "README.md"]
  spec.require_paths = ["lib"]

  spec.add_dependency "rails", ">= 7.0"
  spec.add_dependency "rails-html-sanitizer", ">= 1.6"
  spec.add_dependency "addressable", "~> 2.8"
end
