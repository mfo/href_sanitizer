# frozen_string_literal: true

require "href_sanitizer/link_to_patch"

module HrefSanitizer
  class Railtie < Rails::Railtie
    initializer "href_sanitizer.configure_link_to" do
      ActiveSupport.on_load(:action_view) do
        if HrefSanitizer.harden_link_to
          ActionView::Base.prepend(HrefSanitizer::LinkToPatch)
        end
      end
    end

    initializer "href_sanitizer.configure_validator" do
      ActiveSupport.on_load(:active_record) do
        # Make SafeUrlValidator available as `validates :field, safe_url: true`
      end
    end
  end
end
