# Changelog

## v0.2.0

- Map all 97 effective Subdominator service identities to an offline, versioned rule pack. This is service-count parity, not a claim of equal detection accuracy.
- Add opt-in AWS Elastic Beanstalk and Azure App Service/Traffic Manager name-availability checks. An unavailable name is dismissed only when the provider response refers to the exact final CNAME target; unsupported and inconclusive checks retain the original alert.
- Probe HTTPS and HTTP separately, retain both responses in JSONL, and decode legacy HTTP charsets before matching fingerprints.
- Preserve CNAME chains and NXDOMAIN evidence through the configured system DNS route when it can be identified. Add a bounded parent-authoritative NS check for unresolved DigitalOcean delegations, reported as lower-confidence edge cases.
- Include edge-case rules by default and add `--exclude-edge-cases`. Report `validated`, `candidate`, `edge_case`, `dismissed`, `clean`, and `unknown` separately.
- Update the minimum Go version to 1.26.10 and refresh dependencies after vulnerability review.

## v0.1.0

- Initial macOS and Linux release with a 49-rule offline pack, DNS and HTTP evidence, JSONL output, bounded concurrency, and four platform archives.
