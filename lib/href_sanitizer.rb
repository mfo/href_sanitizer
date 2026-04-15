# frozen_string_literal: true

require "href_sanitizer/version"
require "href_sanitizer/url_sanitizer"
require "href_sanitizer/url_validator"
require "href_sanitizer/railtie" if defined?(Rails::Railtie)

module HrefSanitizer
  FALLBACK_URL = "#"

  mattr_accessor :harden_link_to, default: true
  mattr_accessor :block_private_urls, default: true
  mattr_accessor :fallback_url, default: FALLBACK_URL
  mattr_accessor :on_unsafe_url, default: nil # optional callback ->(url, reason) { }

  def self.configure
    yield self
  end
end
