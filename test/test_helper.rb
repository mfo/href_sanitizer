# frozen_string_literal: true

require "bundler/setup"
require "active_support"
require "active_support/core_ext"
require "active_support/testing/autorun"
require "active_model"
require "rails-html-sanitizer"
require "action_view"
require "rails-dom-testing"
require "href_sanitizer"
require "minitest/mock"

module StubModuleFunction
  # Temporarily replace a module_function for the duration of a block
  def stub_module_function(mod, method, return_value)
    original = mod.method(method)
    mod.singleton_class.silence_redefinition_of_method(method)
    mod.define_singleton_method(method) { |*| return_value }
    yield
  ensure
    mod.singleton_class.silence_redefinition_of_method(method)
    mod.define_singleton_method(method, original)
  end
end
