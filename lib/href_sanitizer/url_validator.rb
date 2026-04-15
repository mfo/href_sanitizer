# frozen_string_literal: true

require "addressable/uri"
require "active_model"
require "rails-html-sanitizer"
require "href_sanitizer/url_sanitizer"

# ActiveModel validator for URLs.
# Registered as `url:` so it's a drop-in replacement for custom URLValidators.
#
# Usage:
#   validates :website, url: true
#   validates :website, url: { no_local: true }, allow_blank: true
#   validates :website, url: { schemes: %w[https] }
#   validates :lien_dpo, url: { accept_email: true }
#
# Class name is UrlValidator, but we also alias as URLValidator
# to support apps with `inflect.acronym 'URL'` (which makes Rails
# resolve `validates :field, url: true` to URLValidator).
class UrlValidator < ActiveModel::EachValidator
  EMAIL_REGEXP = /\A[^@\s]+@[^@\s]+\z/

  def validate_each(record, attribute, value)
    stripped = value.to_s.strip

    # Accept bare email addresses when accept_email: true
    if options.fetch(:accept_email, false) && stripped.match?(EMAIL_REGEXP)
      return
    end

    uri = parse(stripped)
    unless uri
      record.errors.add(attribute, options.fetch(:message, :url))
      return
    end

    allowed_schemes = options.fetch(:schemes, %w[http https])
    unless uri.scheme&.downcase&.in?(allowed_schemes)
      record.errors.add(attribute, options.fetch(:message, :url))
      return
    end

    unless HrefSanitizer::UrlSanitizer.allowed_uri?(stripped)
      record.errors.add(attribute, options.fetch(:message, :url))
      return
    end

    if options.fetch(:no_local, false)
      unless HrefSanitizer::UrlSanitizer.public_url?(stripped)
        record.errors.add(attribute, options.fetch(:message, :private_ip_url))
      end
    end
  end

  private

  def parse(value)
    uri = Addressable::URI.parse(value)
    uri if uri.host.present?
  rescue Addressable::URI::InvalidURIError
    nil
  end
end

# Alias for apps using `inflect.acronym 'URL'`
URLValidator = UrlValidator
