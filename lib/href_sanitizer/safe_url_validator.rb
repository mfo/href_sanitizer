# frozen_string_literal: true

# Backwards compatibility — safe_url: is an alias for url:
require "href_sanitizer/url_validator"
SafeUrlValidator = UrlValidator
