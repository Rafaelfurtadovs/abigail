# Changelog

## v0.3.0

- Discover subdomains before takeover checks using a vendored, security-patched copy of Subfinder v2.17.0's default passive sources, including crt.name. The optional `--native-discovery` mode uses Abigail's direct crt.name, crt.sh, Cert Spotter, and HackerTarget queries. `scan -d` now treats its argument as a root domain, and `scan -l` treats each input line as a root; use `--no-discover` for exact hostnames.
- Add optional bounded DNS wordlist discovery with `--brute` in either passive mode and a `--discover-only` mode to inspect discovered names without takeover checks.
- Prevalidate Subfinder provider configuration and reject public-suffix discovery roots. Set a per-source discovery deadline with `--discovery-timeout` (default 10 minutes), cap results at 50,000 unique hostnames per run by default, and cap SDK responses at 32 MiB. Roots from `-l` share one provider rate limiter.
- Harden the embedded Subfinder HTTP session with HTTPS certificate verification, cross-origin redirect blocking, credential-safe errors, and the same session for Chaos.
- Update vulnerable transitive Go dependencies identified by `govulncheck`; the final scan reports no known vulnerabilities.
- Report partial discovery failures and fail when every passive source fails, instead of silently scanning only the root. Discovery and takeover detection remain incomplete by nature; results require review.

## v0.2.3

- Show the Abigail ASCII banner above the command-line usage text.

## v0.2.2

- Simplify installation and license information in the README. No scanner behavior or rule changes.

## v0.2.1

- Review all 97 service identities in the reference catalog. Retain 53 active rules and record the 44 exclusions with reasons in `rules/coverage.json`. Remove status-only alerts, documented benign account states, generic fingerprints, unsupported or invalid custom-domain routes, stale targets, and a discontinued service.
- Strengthen AWS S3 detection with regional REST and website CNAMEs plus HTTP 404 and `NoSuchBucket`. Add current Surge CNAME and A targets, narrow Cognito to documented prefix domains, restrict Beanstalk to regional names that can be checked, restrict Azure to current resource shapes, use exact DigitalOcean nameservers, and match only the documented Community CNAME for Read the Docs.
- Require NXDOMAIN to apply to a matching final CNAME target; an intermediate provider CNAME no longer inherits a later target's NXDOMAIN. DNS suffixes now require a child label, and the rule parser rejects status-only HTTP rules.
- Add opt-in, read-only Cognito `DescribeUserPoolDomain` validation. An exact existing prefix can dismiss a finding; absence and API failures remain inconclusive.
- Downgrade signatures with generic missing-page evidence or conditional provider protection to `edge_case`. These changes target known false-positive paths but are not proof of higher overall accuracy.

## v0.2.0

- Map all 97 effective Subdominator service identities to an offline, versioned rule pack. This is service-count parity, not a claim of equal detection accuracy.
- Add opt-in AWS Elastic Beanstalk and Azure App Service/Traffic Manager name-availability checks. An unavailable name is dismissed only when the provider response refers to the exact final CNAME target; unsupported and inconclusive checks retain the original alert.
- Probe HTTPS and HTTP separately, retain both responses in JSONL, and decode legacy HTTP charsets before matching fingerprints.
- Preserve CNAME chains and NXDOMAIN evidence through the configured system DNS route when it can be identified. Add a bounded parent-authoritative NS check for unresolved DigitalOcean delegations, reported as lower-confidence edge cases.
- Include edge-case rules by default and add `--exclude-edge-cases`. Report `validated`, `candidate`, `edge_case`, `dismissed`, `clean`, and `unknown` separately.
- Update the minimum Go version to 1.26.10 and refresh dependencies after vulnerability review.

## v0.1.0

- Initial macOS and Linux release with a 49-rule offline pack, DNS and HTTP evidence, JSONL output, bounded concurrency, and four platform archives.
