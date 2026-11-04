# Rule data attribution

The bundled `providers.json` adapts selected entries from:

1. EdOverflow, [can-i-take-over-xyz `fingerprints.json`](https://github.com/EdOverflow/can-i-take-over-xyz/blob/5bd4e12837911c8475486f1da922c9b9c706e632/fingerprints.json), commit `5bd4e12837911c8475486f1da922c9b9c706e632`. The source project licenses its material under [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/).
2. Stratus Security, [Subdominator `custom_fingerprints.json`](https://github.com/Stratus-Security/Subdominator/blob/9f9dfa0383de9ca786a118b8a01d3570cfe5bbd0/Subdominator/custom_fingerprints.json), commit `9f9dfa0383de9ca786a118b8a01d3570cfe5bbd0`. The source repository uses the [MIT License](STRATUS_LICENSE.md).

Changes made for Abigail: selected a conservative subset; normalized provider identifiers and DNS suffixes; converted source fingerprints to literal HTTP body fragments or NXDOMAIN conditions; excluded status-only signatures and source regular expressions that the version 1 rule engine does not support. Each rule retains its pinned `source` URL. The source projects do not endorse Abigail.

The eight bundled `edge_case` entries use HTTP text from the pinned upstream files above. Their DNS target patterns, where absent from the upstream JSON, are adapted from [Subdominator's pinned DNS overrides](https://github.com/Stratus-Security/Subdominator/blob/9f9dfa0383de9ca786a118b8a01d3570cfe5bbd0/Subdominator/SubdomainHijack.cs). An edge-case match is deliberately a lower-confidence observation; provider-side claimability still needs separate confirmation.

The Abigail program code is under the repository's MIT license. The adapted rule data remains subject to the attribution terms above. Changes to the rule data should preserve this notice and record their sources.
