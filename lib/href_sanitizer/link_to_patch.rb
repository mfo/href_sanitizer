# frozen_string_literal: true

module HrefSanitizer
  module LinkToPatch
    # Override link_to to sanitize href values automatically.
    #
    # This catches:
    #   link_to "Click", "javascript:alert(1)"
    #   link_to "Click", user_supplied_url
    #   link_to("javascript:alert(1)") { "Click" }
    #
    # Safe protocols (http, https, mailto, tel) pass through unchanged.
    # Dangerous protocols (javascript:, data:, vbscript:) are replaced with "#".
    #
    def link_to(name = nil, options = nil, html_options = nil, &block)
      if block_given?
        # link_to(url_or_options, html_options = {}) { content }
        # First arg (name) is actually the URL when a block is given
        name = UrlSanitizer.safe_href(name) if name.is_a?(String)
      else
        # link_to(body, url_string, html_options = {})
        # link_to(body, url_options_hash, html_options = {})
        if options.is_a?(String)
          options = UrlSanitizer.safe_href(options)
        end
      end

      super
    end
  end
end
