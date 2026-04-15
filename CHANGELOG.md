# Changelog

## 0.1.1

- Fix: relative paths (e.g. `/dossiers/363`) and fragment URLs (`#section`) are no longer mangled into protocol-relative URLs (`///dossiers/363`). Only schemeless hostnames like `example.com/page` get `//` prepended.

## 0.1.0

- Initial release
- Automatic `link_to` hardening against dangerous protocols (`javascript:`, `data:`, `vbscript:`)
- SSRF protection via private/local IP resolution check
- `SafeUrlValidator` for ActiveModel
- Configurable fallback URL and unsafe URL callback
