# Rule data attribution

The bundled `providers.json` adapts entries from:

1. EdOverflow, [can-i-take-over-xyz `fingerprints.json`](https://github.com/EdOverflow/can-i-take-over-xyz/blob/5bd4e12837911c8475486f1da922c9b9c706e632/fingerprints.json), commit `5bd4e12837911c8475486f1da922c9b9c706e632`. The source project licenses its material under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).
2. Stratus Security, [Subdominator `custom_fingerprints.json`](https://github.com/Stratus-Security/Subdominator/blob/9f9dfa0383de9ca786a118b8a01d3570cfe5bbd0/Subdominator/custom_fingerprints.json), commit `9f9dfa0383de9ca786a118b8a01d3570cfe5bbd0`. The source repository uses the [MIT License](STRATUS_LICENSE.md).

Changes made for Abigail: normalized provider identifiers and DNS selectors; converted source fingerprints to literal or Go RE2 body checks, HTTP status checks, or NXDOMAIN conditions; and classified status-only signatures as `edge_case` even where the source called them vulnerable. The six entries promoted by Subdominator's code from the source catalog's `Not vulnerable` status remain edge cases here. Each rule retains a `source` URL; [coverage.json](coverage.json) records all 97 service mappings and confidence adjustments. Matching a published service identity does not establish that the service can currently be claimed. The source projects do not endorse Abigail.

Many DNS target patterns and corrected HTTP texts are adapted from [Subdominator's pinned overrides](https://github.com/Stratus-Security/Subdominator/blob/9f9dfa0383de9ca786a118b8a01d3570cfe5bbd0/Subdominator/SubdomainHijack.cs). The DigitalOcean nameserver selector follows [DigitalOcean's published DNS nameservers](https://docs.digitalocean.com/products/networking/dns/details/features/), and the Zendesk CNAME selector follows [Zendesk's host-mapping documentation](https://support.zendesk.com/hc/en-us/articles/4408838571930-Host-mapping-Changing-the-URL-of-your-help-center). An edge-case match is deliberately a lower-confidence observation; provider-side claimability still needs separate confirmation.

The Abigail program code is under the repository's MIT license. The adapted rule data remains subject to the attribution terms above. Changes to the rule data should preserve this notice and record their sources.
