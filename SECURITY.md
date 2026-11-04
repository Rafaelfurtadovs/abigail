# Security policy

## Supported versions

Security fixes are made on the latest release and the default branch. Older
releases may not receive patches.

## Reporting a vulnerability

Please report vulnerabilities privately through this repository's GitHub
**Report a vulnerability** feature when available. Include the affected
version or commit, a minimal reproducer, the expected and observed behavior,
and potential impact. Do not put credentials, sensitive target data, or a
working exploit for a real third-party domain in a public issue.

If private reporting is unavailable, ask the maintainer for a private contact
channel before sending sensitive details. Public issues are suitable for
non-sensitive bugs and feature requests.

## Scope and design assumptions

Abigail is a diagnostic scanner. It makes DNS queries and may send HTTP(S)
requests to supplied hostnames. A finding is evidence for review, not
permission to claim a cloud resource, alter a DNS zone, or access data. Run it
only against assets that you own or are authorized to assess.

The optional `--validate` mode contacts supported AWS or Azure availability
APIs using credentials already available to their SDKs. It does not create a
resource or start an interactive login. Run validation only with credentials
and subscriptions you are authorized to use. Do not put tokens or provider
secrets in command arguments, issue reports, fixtures, or scan output.

Provider rules are security-sensitive data. Changes to them should include
source attribution and tests for both true and false matches. Avoid submitting
real customer hostnames or response bodies in tests or issues.
