# Abigail rule format

`providers.json` is a versioned, offline rule set. Abigail does not fetch or execute rules while scanning. The current `schema_version` is `1`.

Each entry in `rules` has the following fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Stable, unique machine identifier. |
| `service` | string | Human-readable provider name. |
| `cname_suffixes` | string array | DNS names matched on a label boundary: `x.example.com` and `example.com` match `example.com`, but `notexample.com` does not. Values have no leading dot. |
| `cname_exact` | string array | Exact CNAME target names, after lowercasing and removing a trailing dot. |
| `a_records`, `aaaa_records` | string arrays | Exact IPv4 and IPv6 addresses. A future rule may use them; no bundled rule currently does. |
| `http_statuses` | integer array | Acceptable HTTP response codes. |
| `body_substrings` | string array | Literal, case-sensitive fragments in the HTTP response body. These are not regular expressions. |
| `target_nxdomain` | boolean | Requires the resolved CNAME target to return NXDOMAIN. Used only when both HTTP arrays are empty. |
| `status` | string | Source catalog classification: `vulnerable` or `edge_case`. This is not the scanner's finding verdict. |
| `source` | URL string | Pinned upstream file from which this rule was adapted. |

A DNS record match is required before checking HTTP or NXDOMAIN evidence. Values within `http_statuses` are alternatives; values within `body_substrings` are alternatives. If both arrays are nonempty, **a matching status and a matching body fragment are both required**. NXDOMAIN is a separate evidence mode and must not be combined with HTTP conditions.

An alert means the observations match a published signature. It does not prove that the resource can be claimed. Rule updates should include a reproducible positive fixture, a negative fixture, and a source or provider verification explaining why the service is still claimable. See [NOTICE.md](NOTICE.md) for provenance and licensing.
