# Embedded Subfinder source

This directory contains the production `pkg/` source from ProjectDiscovery
Subfinder v2.17.0, licensed under the included [MIT license](LICENSE.md).
The package import paths were changed to the Abigail module path. Upstream's
test files, CLI, and examples are not included.

Abigail patches `pkg/subscraping/agent.go` to verify HTTPS certificates,
block redirects to another origin, and avoid exposing credential-bearing URLs
or response bodies in source errors and logs. The Chaos source now uses that
verified session client instead of its former separate HTTP client. The runner
shares provider rate limits across roots and caps per-source results and HTTP
response bodies. It stores provider configuration under Abigail's application
config directory (or `ABIGAIL_PROVIDER_CONFIG`) and leaves progress and source
error summaries to Abigail's CLI. Focused regression tests live beside the
patched packages. See
[third-party notices](../../THIRD_PARTY_NOTICES.md) for the source version and
license terms.
