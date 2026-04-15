# frozen_string_literal: true

require "addressable/uri"
require "cgi"
require "resolv"
require "ipaddr"

module HrefSanitizer
  module UrlSanitizer
    PRIVATE_RANGES = [
      IPAddr.new("0.0.0.0/8"),
      IPAddr.new("10.0.0.0/8"),
      IPAddr.new("100.64.0.0/10"),
      IPAddr.new("127.0.0.0/8"),
      IPAddr.new("169.254.0.0/16"),
      IPAddr.new("172.16.0.0/12"),
      IPAddr.new("192.0.0.0/24"),
      IPAddr.new("192.168.0.0/16"),
      IPAddr.new("198.18.0.0/15"),
      IPAddr.new("::1/128"),
      IPAddr.new("fc00::/7"),
      IPAddr.new("fe80::/10"),
      IPAddr.new("::ffff:127.0.0.0/104"),
      IPAddr.new("::ffff:10.0.0.0/104"),
      IPAddr.new("::ffff:172.16.0.0/108"),
      IPAddr.new("::ffff:192.168.0.0/112")
    ].freeze

    SAFE_PROTOCOLS = Set.new(%w[http https mailto tel]).freeze

    module_function

    # Check if a URI string uses a safe protocol.
    # Uses Rails::HTML::Sanitizer.allowed_uri? when available (rails-html-sanitizer >= 1.7),
    # falls back to our own scheme check for older versions.
    def allowed_uri?(uri_string)
      if Rails::HTML::Sanitizer.respond_to?(:allowed_uri?)
        Rails::HTML::Sanitizer.allowed_uri?(uri_string)
      else
        unescaped = CGI.unescapeHTML(uri_string).gsub(/[\x00-\x1f]/, "").downcase
        # If no scheme detected, it's a relative URL — allow it
        return true unless unescaped =~ /\A[a-z][a-z0-9+\-.]*:/

        scheme = unescaped.split(":").first
        SAFE_PROTOCOLS.include?(scheme)
      end
    end

    # Sanitize a URL for safe use in href attributes.
    # Returns the safe URL or the fallback.
    def safe_href(value)
      return HrefSanitizer.fallback_url if value.blank?

      stripped = value.to_s.strip

      uri = Addressable::URI.parse(stripped)

      # Detect bare email addresses (no scheme)
      if uri.scheme.nil? && stripped.match?(/\A[^@\s]+@[^@\s]+\z/)
        return "mailto:#{stripped}"
      end

      if allowed_uri?(stripped)
        if uri.scheme.nil?
          if stripped.start_with?("/") || stripped.start_with?("#")
            stripped
          else
            "//#{stripped.delete_prefix('//')}"
          end
        else
          stripped
        end
      else
        notify_unsafe(stripped, :dangerous_scheme)
        HrefSanitizer.fallback_url
      end
    rescue Addressable::URI::InvalidURIError
      notify_unsafe(value, :invalid_uri)
      HrefSanitizer.fallback_url
    end

    # Check if a URL resolves to a private/local IP (SSRF protection).
    # Returns true if the URL is safe (public), false if it targets private infrastructure.
    def public_url?(value)
      return false if value.blank?

      uri = Addressable::URI.parse(value.to_s.strip)
      return false unless uri.scheme&.downcase&.in?(%w[http https])

      host = uri.host
      return false if host.blank?

      # Direct IP check
      if valid_ip?(host)
        return !private_ip?(host)
      end

      # Convert IDN (unicode) hostnames to ASCII punycode for DNS resolution
      ascii_host = uri.normalized_host || host

      # DNS resolution check — resolve the hostname and verify all IPs are public
      resolved_ips = resolve_host(ascii_host)
      return false if resolved_ips.empty?

      resolved_ips.none? { |ip| private_ip?(ip) }
    rescue Addressable::URI::InvalidURIError
      false
    end

    def private_ip?(ip_string)
      ip = IPAddr.new(ip_string)
      PRIVATE_RANGES.any? { |range| range.include?(ip) }
    rescue IPAddr::InvalidAddressError
      true
    end

    def valid_ip?(string)
      IPAddr.new(string)
      true
    rescue IPAddr::InvalidAddressError
      false
    end

    def resolve_host(host)
      Resolv::DNS.open do |dns|
        a_records = dns.getresources(host, Resolv::DNS::Resource::IN::A).map { it.address.to_s }
        aaaa_records = dns.getresources(host, Resolv::DNS::Resource::IN::AAAA).map { it.address.to_s }
        a_records + aaaa_records
      end
    rescue Resolv::ResolvError, Resolv::ResolvTimeout
      []
    end

    def notify_unsafe(url, reason)
      HrefSanitizer.on_unsafe_url&.call(url, reason)
    end
  end
end
