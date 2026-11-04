# Contributing to Abigail

Thanks for helping improve Abigail. Contributions that improve accuracy,
clarity, or maintainability are welcome.

## Before submitting a pull request

1. Open an issue for substantial behavior changes so the design can be
   discussed before implementation.
2. Keep changes focused and explain what evidence supports any new detection
   rule or validator. Include a source link and the date checked.
3. Add local, deterministic tests for positive, negative, and ambiguous cases.
   Do not make tests depend on a third-party hostname remaining vulnerable.
4. Run `go test ./...` and `go vet ./...`.
5. Do not include secrets, customer domains, scan output, or data from systems
   you do not have permission to assess.

## Detection rules

An HTTP error page or a matching CNAME alone does not always prove takeover.
New rules should document the provider's ownership model and when a resource
can actually be claimed. Prefer a safe provider API check over an active claim.
If the state cannot be determined reliably, report it as uncertain.

## Responsible use

Contributors and users are responsible for complying with applicable law,
contracts, and authorization boundaries. Do not submit functionality that
claims resources, extracts data, or evades target protections as part of a
routine scan.

By contributing, you agree that your contributions are licensed under the
project's MIT license.
