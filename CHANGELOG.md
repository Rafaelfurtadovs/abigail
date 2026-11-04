# Changelog

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
