# Rule coverage against Subdominator

The reference is [Subdominator commit `9f9dfa0`](https://github.com/Stratus-Security/Subdominator/tree/9f9dfa0383de9ca786a118b8a01d3570cfe5bbd0) and its upstream [can-i-take-over-xyz commit `5bd4e12`](https://github.com/EdOverflow/can-i-take-over-xyz/tree/5bd4e12837911c8475486f1da922c9b9c706e632). The source catalog has 76 services: 50 are active, 26 are marked `Not vulnerable`. Subdominator's code promotes six of the latter to edge cases and adds 41 unique custom services. Thus its effective service count is **97**.

Abigail's bundled rule pack maps those **97 distinct service identities** to **97 rules**. The complete machine-readable comparison is [rules/coverage.json](../rules/coverage.json). GitHub is called “GitHub Pages” in Abigail. Some signatures have been downgraded to `edge_case` when the only service evidence is an HTTP status or a generic fingerprint.

Of the 97 rules, 79 use HTTP body evidence (two also contain a Go RE2 body pattern), 10 use HTTP status alone and are always edge cases, and eight use NXDOMAIN evidence. One NXDOMAIN rule also requires DigitalOcean nameserver evidence. There are 61 rules classified `vulnerable` by the bundled data and 36 classified `edge_case`. An offline consistency test checks that every reference service maps to a distinct existing rule, that the 97-count does not regress, and that all rule definitions parse.

This is **count parity, not demonstrated detection parity**. A rule can be stale, a provider can change claimability, and two scanners can disagree on the same DNS/HTTP response. To substantiate a quality claim, use the labeled, authorized corpus and metrics in [ACCURACY.md](ACCURACY.md). In particular, compare true positives, false positives, unknown outcomes, provider coverage, and runtime against pinned builds. Do not count a rule as a confirmed takeover merely because a fingerprint matched.

NXDOMAIN checks require a complete DNS chain. On macOS and Linux, Abigail can
obtain it through the default system DNS route when that route is unambiguous;
otherwise, `--resolver` selects a server explicitly. The DigitalOcean rule
combines NS and NXDOMAIN evidence and remains an edge case. If the exact child
NS delegation is verified at a parent authority but child resolution fails,
it may instead report `delegation_unresolved: true` without an observed
NXDOMAIN; that remains an edge case, not a confirmed takeover. Status-only
signatures are also edge cases. Provider-side availability checks, where
supported, remain a separate validation step. No service is omitted from the
identity mapping, but mapping does not prove that any specific provider is
currently claimable or that all its current response encodings are covered.
