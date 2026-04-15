# frozen_string_literal: true

require "test_helper"
require "href_sanitizer/url_validator"

class URLValidatorTest < ActiveSupport::TestCase
  include StubModuleFunction

  setup do
    validator = HrefSanitizer::UrlValidator

    @model_class = Class.new do
      include ActiveModel::Model
      include ActiveModel::Validations

      attr_accessor :website

      validates_with validator, attributes: [:website], no_local: true, allow_blank: true

      def self.name = "TestModel"
    end

    @email_model_class = Class.new do
      include ActiveModel::Model
      include ActiveModel::Validations

      attr_accessor :lien_dpo

      validates_with validator, attributes: [:lien_dpo], no_local: true, accept_email: true, allow_blank: true

      def self.name = "EmailModel"
    end
  end

  # --- valid public URLs ---

  test "valid with https URL" do
    stub_module_function(HrefSanitizer::UrlSanitizer, :public_url?, true) do
      record = @model_class.new(website: "https://example.com")
      assert record.valid?
    end
  end

  test "valid with http URL and query string" do
    stub_module_function(HrefSanitizer::UrlSanitizer, :public_url?, true) do
      record = @model_class.new(website: "http://example.com/path?q=1")
      assert record.valid?
    end
  end

  test "valid with subdomain gouv.fr URL" do
    stub_module_function(HrefSanitizer::UrlSanitizer, :public_url?, true) do
      record = @model_class.new(website: "https://sous-domaine.gouv.fr")
      assert record.valid?
    end
  end

  # --- blank values ---

  test "valid when blank and allow_blank: true" do
    record = @model_class.new(website: "")
    assert record.valid?
  end

  # --- dangerous schemes ---

  test "invalid with javascript: scheme" do
    record = @model_class.new(website: "javascript:alert(1)")
    assert_not record.valid?
    assert record.errors[:website].any?
  end

  test "invalid with data: scheme" do
    record = @model_class.new(website: "data:text/html,xss")
    assert_not record.valid?
    assert record.errors[:website].any?
  end

  test "invalid with ftp: scheme" do
    record = @model_class.new(website: "ftp://files.example.com")
    assert_not record.valid?
    assert record.errors[:website].any?
  end

  # --- SSRF: private/local URLs ---

  test "invalid with localhost" do
    record = @model_class.new(website: "http://127.0.0.1")
    assert_not record.valid?
  end

  test "invalid with private IP 192.168.x.x" do
    record = @model_class.new(website: "http://192.168.1.1")
    assert_not record.valid?
  end

  test "invalid with cloud metadata endpoint" do
    record = @model_class.new(website: "http://169.254.169.254/latest/meta-data")
    assert_not record.valid?
  end

  # --- DNS rebinding ---

  test "invalid when DNS resolves to private IP" do
    stub_module_function(HrefSanitizer::UrlSanitizer, :resolve_host, ["10.0.0.1"]) do
      record = @model_class.new(website: "https://evil.com")
      assert_not record.valid?
    end
  end

  # --- garbage input ---

  test "invalid with garbage input" do
    record = @model_class.new(website: "not a url at all")
    assert_not record.valid?
  end

  test "invalid with schemeless URL" do
    record = @model_class.new(website: "www.example.com")
    assert_not record.valid?
  end

  # --- accept_email ---

  test "accept_email allows bare email addresses" do
    record = @email_model_class.new(lien_dpo: "dpo@example.com")
    assert record.valid?
  end

  test "accept_email still allows https URLs" do
    stub_module_function(HrefSanitizer::UrlSanitizer, :public_url?, true) do
      record = @email_model_class.new(lien_dpo: "https://example.com/dpo")
      assert record.valid?
    end
  end

  test "accept_email rejects javascript: protocol" do
    record = @email_model_class.new(lien_dpo: "javascript:alert(1)")
    assert_not record.valid?
  end

  test "accept_email allows blank when allow_blank: true" do
    record = @email_model_class.new(lien_dpo: "")
    assert record.valid?
  end

  # --- without accept_email, email is rejected ---

  test "without accept_email rejects bare email" do
    record = @model_class.new(website: "test@example.com")
    assert_not record.valid?
  end

  # --- IDN / unicode URLs ---

  test "valid with accented domain name" do
    stub_module_function(HrefSanitizer::UrlSanitizer, :public_url?, true) do
      record = @model_class.new(website: "https://www.démarches-simplifiées.fr")
      assert record.valid?
    end
  end

  test "invalid with schemeless accented domain" do
    record = @model_class.new(website: "www.démarches-simplifiées.fr")
    assert_not record.valid?
  end
end
