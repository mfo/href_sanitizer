# frozen_string_literal: true

require "test_helper"
require "href_sanitizer/link_to_patch"
require "action_view/helpers"
require "rails/dom/testing/assertions"

class LinkToPatchTest < ActiveSupport::TestCase
  include Rails::Dom::Testing::Assertions::DomAssertions

  setup do
    view_class = Class.new(ActionView::Base) do
      prepend HrefSanitizer::LinkToPatch
    end
    @view = view_class.with_empty_template_cache.empty
    @view.output_buffer = ActionView::OutputBuffer.new
  end

  test "link_to allows safe https URLs" do
    assert_dom_equal(
      %(<a href="https://example.com">Example</a>),
      @view.link_to("Example", "https://example.com")
    )
  end

  test "link_to blocks javascript: URLs" do
    html = @view.link_to("Click me", "javascript:alert(1)")
    assert_includes html, 'href="#"'
    assert_not_includes html, "javascript"
  end

  test "link_to blocks data: URLs" do
    html = @view.link_to("Click me", "data:text/html,<script>alert(1)</script>")
    assert_includes html, 'href="#"'
  end

  test "link_to allows mailto: URLs" do
    assert_dom_equal(
      %(<a href="mailto:test@example.com">Email</a>),
      @view.link_to("Email", "mailto:test@example.com")
    )
  end

  test "link_to converts bare email to mailto" do
    assert_dom_equal(
      %(<a href="mailto:dpo@example.com">DPO</a>),
      @view.link_to("DPO", "dpo@example.com")
    )
  end

  test "link_to with block form blocks javascript:" do
    html = @view.link_to("javascript:alert(1)") { "Click" }
    assert_includes html, 'href="#"'
  end

  test "link_to does not interfere with hash options" do
    assert_raises(ArgumentError, match: /url_for/) do
      @view.link_to("Home", { controller: "home", action: "index" })
    end
  end

  test "link_to preserves html_options" do
    html = @view.link_to("Example", "https://example.com", class: "btn", target: "_blank")
    assert_includes html, 'class="btn"'
    assert_includes html, 'target="_blank"'
  end
end
