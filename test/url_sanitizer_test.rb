# frozen_string_literal: true

require "test_helper"

class UrlSanitizerTest < ActiveSupport::TestCase
  include StubModuleFunction

  # --- safe_href: safe URLs pass through ---

  test "safe_href allows https URLs" do
    assert_equal "https://example.com/faq", HrefSanitizer::UrlSanitizer.safe_href("https://example.com/faq")
  end

  test "safe_href allows http URLs" do
    assert_equal "http://example.com", HrefSanitizer::UrlSanitizer.safe_href("http://example.com")
  end

  test "safe_href allows mailto URLs" do
    assert_equal "mailto:dpo@example.com", HrefSanitizer::UrlSanitizer.safe_href("mailto:dpo@example.com")
  end

  test "safe_href allows tel URLs" do
    assert_equal "tel:+33123456789", HrefSanitizer::UrlSanitizer.safe_href("tel:+33123456789")
  end

  test "safe_href converts bare email addresses to mailto" do
    assert_equal "mailto:dpo@example.com", HrefSanitizer::UrlSanitizer.safe_href("dpo@example.com")
  end

  test "safe_href adds // to schemeless URLs" do
    assert_equal "//example.com/page", HrefSanitizer::UrlSanitizer.safe_href("example.com/page")
  end

  test "safe_href keeps protocol-relative URLs" do
    assert_equal "//example.com/page", HrefSanitizer::UrlSanitizer.safe_href("//example.com/page")
  end

  test "safe_href preserves absolute paths" do
    assert_equal "/dossiers/363", HrefSanitizer::UrlSanitizer.safe_href("/dossiers/363")
  end

  test "safe_href preserves nested absolute paths" do
    assert_equal "/dossiers/675/modifier", HrefSanitizer::UrlSanitizer.safe_href("/dossiers/675/modifier")
  end

  test "safe_href preserves fragment-only URLs" do
    assert_equal "#section", HrefSanitizer::UrlSanitizer.safe_href("#section")
  end

  # --- safe_href: dangerous protocols are blocked ---

  test "safe_href blocks javascript: protocol" do
    assert_equal "#", HrefSanitizer::UrlSanitizer.safe_href("javascript:alert(1)")
  end

  test "safe_href blocks JavaScript: mixed case" do
    assert_equal "#", HrefSanitizer::UrlSanitizer.safe_href("JavaScript:alert(document.cookie)")
  end

  test "safe_href blocks data: protocol" do
    assert_equal "#", HrefSanitizer::UrlSanitizer.safe_href("data:text/html,<script>alert(1)</script>")
  end

  test "safe_href blocks vbscript: protocol" do
    assert_equal "#", HrefSanitizer::UrlSanitizer.safe_href("vbscript:MsgBox('XSS')")
  end

  # --- safe_href: edge cases ---

  test "safe_href returns fallback for nil" do
    assert_equal "#", HrefSanitizer::UrlSanitizer.safe_href(nil)
  end

  test "safe_href returns fallback for empty string" do
    assert_equal "#", HrefSanitizer::UrlSanitizer.safe_href("")
  end

  test "safe_href returns fallback for whitespace" do
    assert_equal "#", HrefSanitizer::UrlSanitizer.safe_href("   ")
  end

  test "safe_href strips whitespace padding" do
    assert_equal "https://example.com", HrefSanitizer::UrlSanitizer.safe_href("  https://example.com  ")
  end

  # --- public_url?: public IPs ---

  test "public_url? returns true for public URLs" do
    stub_module_function(HrefSanitizer::UrlSanitizer, :resolve_host, ["93.184.216.34"]) do
      assert HrefSanitizer::UrlSanitizer.public_url?("https://example.com")
    end
  end

  # --- public_url?: private IPs ---

  test "public_url? returns false for localhost" do
    assert_not HrefSanitizer::UrlSanitizer.public_url?("http://127.0.0.1/admin")
  end

  test "public_url? returns false for 192.168.x.x" do
    assert_not HrefSanitizer::UrlSanitizer.public_url?("http://192.168.1.1")
  end

  test "public_url? returns false for 10.x.x.x" do
    assert_not HrefSanitizer::UrlSanitizer.public_url?("http://10.0.0.1")
  end

  test "public_url? returns false for 172.16.x.x" do
    assert_not HrefSanitizer::UrlSanitizer.public_url?("http://172.16.0.1")
  end

  test "public_url? returns false for cloud metadata endpoint" do
    assert_not HrefSanitizer::UrlSanitizer.public_url?("http://169.254.169.254/latest/meta-data")
  end

  test "public_url? returns false for IPv6 loopback" do
    assert_not HrefSanitizer::UrlSanitizer.public_url?("http://[::1]/admin")
  end

  test "public_url? returns false when DNS resolves to private IP" do
    stub_module_function(HrefSanitizer::UrlSanitizer, :resolve_host, ["127.0.0.1"]) do
      assert_not HrefSanitizer::UrlSanitizer.public_url?("https://evil.com/steal")
    end
  end

  test "public_url? returns false for blank values" do
    assert_not HrefSanitizer::UrlSanitizer.public_url?(nil)
    assert_not HrefSanitizer::UrlSanitizer.public_url?("")
  end

  test "public_url? returns false for non-http schemes" do
    assert_not HrefSanitizer::UrlSanitizer.public_url?("ftp://example.com")
  end

  # --- private_ip? ---

  { "127.0.0.1" => true, "10.0.0.1" => true, "172.16.0.1" => true,
    "192.168.1.1" => true, "169.254.169.254" => true, "100.64.0.1" => true,
    "::1" => true, "93.184.216.34" => false, "8.8.8.8" => false,
    "2606:4700::" => false }.each do |ip, expected|
    test "private_ip? #{ip} is #{expected ? 'private' : 'public'}" do
      assert_equal expected, HrefSanitizer::UrlSanitizer.private_ip?(ip)
    end
  end
end
