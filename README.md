# Abigail

Abigail is an open-source Go scanner for potential subdomain takeovers. It checks DNS and provider-specific responses; findings require manual confirmation.

## Install (macOS and Linux)

With Go 1.26.10 or newer:

```sh
go install github.com/Rafaelfurtadovs/abigail/cmd/abigail@v0.2.2
```

The binary is placed in `GOBIN` or, by default, `$(go env GOPATH)/bin`. Without Go, download the archive for your system from the [v0.2.2 release](https://github.com/Rafaelfurtadovs/abigail/releases/tag/v0.2.2), verify it against `SHA256SUMS`, and extract it.

## License

The code is licensed under [MIT](LICENSE). Adapted rule data has separate attribution terms in [rules/NOTICE.md](rules/NOTICE.md). Use Abigail only on authorized targets; the maintainers are not responsible for misuse.
