# href_sanitizer

Drop-in Rails engine that hardens `link_to` against dangerous protocols (`javascript:`, `data:`, `vbscript:`) and provides URL validation to prevent SSRF via private/local IP resolution.

## Installation

```ruby
gem "href_sanitizer"
```

## Usage

Everything is enabled by default. Add the gem and `link_to` is automatically patched.

To configure:

```ruby
HrefSanitizer.configure do |config|
  config.harden_link_to = true       # patch link_to (default: true)
  config.block_private_urls = true   # block private/local IPs (default: true)
  config.fallback_url = "#"          # replacement for unsafe URLs (default: "#")
  config.on_unsafe_url = ->(url, reason) { Rails.logger.warn("Blocked: #{url}") }
end
```

## License

MIT
