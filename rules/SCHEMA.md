# Abigail rule format

`providers.json` is a versioned, offline rule set. Abigail does not fetch or execute rules while scanning. The current `schema_version` is `1`.

Each entry in `rules` has the following fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Stable, unique machine identifier. |
| `service` | string | Human-readable provider name. |
| `cname_suffixes` | string array | DNS names matched on a label boundary: `x.example.com` and `example.com` match `example.com`, but `notexample.com` does not. Values have no leading dot. |
| `cname_exact` | string array | Exact CNAME target names, after lowercasing and removing a trailing dot. |
| `cname_regexes` | string array | Go RE2 expressions matched against a normalized CNAME target. Anchor a pattern when an exact shape is required. |
| `a_records`, `aaaa_records` | string arrays | Exact IPv4 and IPv6 addresses. |
| `ns_suffixes` | string array | Name-server targets matched on a DNS label boundary. A direct DNS route is needed; Abigail can obtain one from the system configuration when unambiguous, or from `--resolver`. |
| `http_statuses` | integer array | Acceptable HTTP response codes. |
| `body_substrings` | string array | Literal, case-sensitive fragments in the HTTP response body. These are not regular expressions. |
| `body_regexes` | string array | Go RE2 expressions matched against the bounded HTTP body. |
| `target_nxdomain` | boolean | The ordinary rule path requires a complete DNS observation of NXDOMAIN at a matching CNAME target or delegated name. Used only when HTTP conditions are empty. The DigitalOcean edge-case exception below may instead report unresolved delegation. |
| `status` | string | Abigail's confidence category: `vulnerable` or `edge_case`. This is not proof of claimability. |
| `source` | URL string | Public source for the rule. Source repository links are pinned to commits. |

A DNS record match is required before checking HTTP or NXDOMAIN evidence. Exact, suffix, and regex DNS matchers are alternatives. Values within `http_statuses` are alternatives, as are the literal and regex body fingerprints. If both status and body conditions are present, **both are required**. A status-only rule is allowed only as an `edge_case`: status alone cannot justify a high-confidence result. NXDOMAIN is a separate evidence mode and must not be combined with HTTP conditions. Complete CNAME-chain and NS evidence requires a direct DNS route, obtained from an unambiguous system configuration or an explicit `--resolver`.

For the DigitalOcean NS rule only, Abigail may emit a lower-confidence finding
with `delegation_unresolved: true` when it verifies the exact child NS
delegation at a parent authority but the child lookup cannot be completed.
That result omits `target_nxdomain` evidence: no NXDOMAIN was observed, and
claimability is unknown. A recursive resolver's ordinary parent NS records do
not satisfy this exception.

An alert means the observations match a published signature. It does not prove that the resource can be claimed. Rule updates should include a reproducible positive fixture, a negative fixture, and a source or provider verification explaining why the service is still claimable. See [coverage.json](coverage.json) for the service mapping and [NOTICE.md](NOTICE.md) for provenance and licensing.
