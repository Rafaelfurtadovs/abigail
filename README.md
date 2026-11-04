# Abigail

Abigail is an open-source Go tool that discovers subdomains and checks them for potential takeovers using DNS and provider-specific responses. Run `abigail scan -d example.com` to discover and check a domain. Findings require manual confirmation; see the [discovery guide](docs/DISCOVERY.md).

## Install (macOS and Linux)

With Go 1.26.10 or newer:

```sh
go install github.com/Rafaelfurtadovs/abigail/cmd/abigail@v0.3.0
```

The binary is placed in `GOBIN` or, by default, `$(go env GOPATH)/bin`. Without Go, download the archive for your system from the [v0.3.0 release](https://github.com/Rafaelfurtadovs/abigail/releases/tag/v0.3.0), verify it against `SHA256SUMS`, and extract it.

## License

The code is licensed under [MIT](LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md), [dependency licenses](licenses/NOTICE.md), and [rule attribution](rules/NOTICE.md). Use Abigail only on authorized targets; the maintainers are not responsible for misuse.
