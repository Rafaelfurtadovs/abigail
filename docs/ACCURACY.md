# Evaluating detection accuracy

Abigail is not described as more accurate or faster than another scanner until
the claim is supported by a published, reproducible evaluation. This document
defines how to compare Abigail with Subdominator or another tool.

## Build the labeled corpus

Use only hostnames and provider resources that the evaluator owns or is
explicitly authorized to test. Record the authorization scope separately from
any public dataset. Keep sensitive hostnames and response bodies out of the
public report; publish anonymized case IDs and sufficient non-sensitive
evidence to reproduce the classification.

For each case, record the provider, DNS records and CNAME chain, HTTP status
and relevant response fragment for **both HTTPS and HTTP**, observation time,
and **ground truth**:

- **Positive:** a controlled, owned test setup demonstrates that the referenced
  resource can be re-registered, or independent provider evidence establishes
  the same result. An API response used by the scanner is not sufficient as
  the sole ground-truth source. Never claim someone else's resource.
- **Negative:** an owned, active resource or a provider check confirms the
  reference cannot be claimed. Include error pages and CNAMEs that resemble
  positive fingerprints.
- **Indeterminate:** ownership cannot be established safely or reliably. Keep
  these cases in the corpus, but exclude them from precision and recall
  denominators and report them separately.

Cover multiple providers and DNS patterns, including chained CNAMEs, A/AAAA
targets, NXDOMAIN, redirects, invalid TLS, timeouts, and stale or ambiguous
provider error pages. Keep a separate local fixture suite for deterministic
regression tests; do not count simulated cases as real-world ground truth.
Have two reviewers label real cases independently and resolve disagreements
before looking at either scanner's verdict.

## Pin the experiment

Publish the Abigail and comparator commit or release, binary SHA-256 values,
rule-pack revision or SHA-256, corpus revision, observation date, OS and
architecture, DNS resolver, timeout, concurrency, any rate limit, and whether
provider validation was enabled. Record the operating system's HTTP name
resolution route separately from Abigail's `--resolver`: in split-DNS
environments they can see different targets. Use the
same hostname list and equivalent scan settings. Run each tool on the same
network within a short time window, because DNS and provider state can change.
Randomize tool order across repetitions and report both cold and warm runs if
caching affects results. Preserve raw JSONL or text outputs privately for
review; publish a redacted per-case verdict table and the evaluation script.

## Score outcomes

Map each tool's output to **positive**, **negative**, or **unknown** before
computing metrics. For Abigail, `validated`, `candidate`, and `edge_case` are
positive alerts at separate confidence tiers; `clean` and `dismissed` are
negative scanner outputs, not proof that the target is safe; and `unknown`
stays unknown. A finding with `validation.state=unavailable` appears under
`dismissed` rather than active `findings`; review those cases separately for
false dismissal.
Validation states `unknown` and `unsupported` do not establish a negative.
Do not count an unknown scan as a true negative. Apply an equivalent published
mapping to the comparator's output, including errors and unsupported cases.

On cases with positive or negative ground truth, report the full confusion
matrix: true positives (TP), false positives (FP), false negatives (FN), and
true negatives (TN). Report:

- **Precision:** `TP / (TP + FP)`.
- **Recall:** `TP / (TP + FN)`.
- **False-positive rate:** `FP / (FP + TN)`.
- **Unknown rate:** unknown outputs divided by all evaluated cases, separately
  for positive and negative ground truth.
- **Coverage:** providers and cases for which each tool has an applicable rule.
- **Validation availability:** counts of `available`, `unavailable`, `unknown`,
  and `unsupported` by provider when direct validation is enabled.

Show counts as well as percentages, both overall and per provider. Report
metrics separately for fingerprint-only and validation-enabled scans, and with
`edge_case` included and excluded. A provider with no direct validator must
not be treated as validation-negative. For small samples, include confidence
intervals and avoid ranking tools on a tiny difference.

Report DigitalOcean findings marked `delegation_unresolved` separately from
observed NXDOMAIN cases. Parent-authoritative delegation plus a failed child
lookup is incomplete evidence; it is not proof that the name is claimable.

## Measure performance

Use the same machine and network conditions. Record wall-clock runtime for
each complete run, hostnames processed per second, and peak memory. Repeat
each run at least three times and report the median and range. Account for
timeouts and unknown results rather than rewarding a tool that skips checks.
Do not substitute the number of alerts for accuracy.

## Review every false positive and false negative

For each disagreement, capture the rule, DNS and HTTP evidence, the provider's
current ownership policy, and the reason for the ground-truth label. Mark a
case stale when the provider changes behavior; re-label it before reuse. Feed
confirmed errors into regression fixtures, then rerun the complete corpus.

Only make a comparative claim when its scope is explicit: corpus size and
composition, versions, settings, confidence tier, metric, and uncertainty.
For example, a precision improvement on one provider is not evidence of
overall superiority.
