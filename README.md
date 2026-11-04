# Abigail

Abigail is an open-source command-line scanner for **potential subdomain
takeovers**. It checks DNS records and provider-specific HTTP evidence, then
reports what it observed so a human can decide what to investigate next.

Abigail is designed around reproducible findings: a provider name, the DNS
record that matched, the HTTP evidence when relevant, and an explicit outcome
when the available evidence is insufficient. It does **not** register a domain,
claim a cloud resource, modify DNS, or exploit a target.

> **Project status:** Early development. Detection coverage and performance
> have not yet been independently benchmarked against other scanners. Treat
> all findings as leads until independently confirmed. See the
> [evaluation protocol](docs/ACCURACY.md) for how comparative claims will be
> measured.

## Features

- Scan one hostname or a line-delimited file of hostnames.
- Resolve CNAME, A, and AAAA records. With an explicit DNS resolver, inspect
  the full CNAME chain and NXDOMAIN responses.
- Use versioned, reviewable provider rules embedded in the executable rather
  than an unpinned runtime download.
- Separate positive matches from unknown or incomplete checks.
- Write machine-readable JSON Lines output for CI or further analysis.
- Bound concurrency and per-host timeouts.

## Requirements

- macOS or Linux, on a platform supported by the installed Go toolchain.
- Go 1.25 or newer, as specified by [`go.mod`](go.mod).
- Network access for DNS lookups and, when a rule requires it, HTTP(S) checks.

No administrator privileges are required. Run Abigail as an ordinary user.

## Download a release without Go

Download the archive for your system and `SHA256SUMS` from the
[v0.1.0 release](https://github.com/Rafaelfurtadovs/abigail/releases/tag/v0.1.0):

| System | Archive |
| --- | --- |
| macOS, Apple Silicon | `abigail_v0.1.0_darwin_arm64.tar.gz` |
| macOS, Intel | `abigail_v0.1.0_darwin_amd64.tar.gz` |
| Linux, x86-64 | `abigail_v0.1.0_linux_amd64.tar.gz` |
| Linux, ARM64 | `abigail_v0.1.0_linux_arm64.tar.gz` |

Check your archive's digest against its entry in `SHA256SUMS` with
`shasum -a 256 ARCHIVE` on macOS or `sha256sum ARCHIVE` on Linux. Then run:

```sh
mkdir abigail-release
tar -xzf ARCHIVE -C abigail-release
./abigail-release/abigail version
```

Replace `ARCHIVE` with the downloaded filename. The macOS archives are not
Apple signed or notarized; building from source below is available if your
device policy does not allow unsigned downloads.

## Build on macOS and Linux

1. Install Go from the [official Go downloads page](https://go.dev/dl/) and
   verify it is on your `PATH`:

   ```sh
   go version
   ```

2. Clone the repository and build Abigail:

   ```sh
   git clone https://github.com/Rafaelfurtadovs/abigail.git
   cd abigail
   go build -o abigail ./cmd/abigail
   ```

3. Check the command-line help:

   ```sh
   ./abigail --help
   ```

These commands are the same on macOS and Linux. The resulting `abigail`
executable is built for the machine on which `go build` runs and includes the
default rule pack. To remove it, delete that executable; Abigail does not
require a system-wide installation.

You can also install the latest public module version with:

```sh
go install github.com/Rafaelfurtadovs/abigail/cmd/abigail@latest
```

Go places the command in `GOBIN` when set, otherwise in `$(go env GOPATH)/bin`.
Add that directory to your `PATH` to invoke `abigail` without `./`.

### Optional: make the command available on your PATH

Copy the binary into a directory already on your `PATH`, or use an existing
user-owned `~/bin` directory:

```sh
mkdir -p "$HOME/bin"
cp ./abigail "$HOME/bin/abigail"
```

If `~/bin` is not on your `PATH`, add it using your shell's normal
configuration. You can always run `./abigail` from the repository directory
without changing `PATH`.

## Quick start

Scan one authorized hostname:

```sh
./abigail scan -d sub.example.com
```

Scan a file with one hostname per line:

```sh
./abigail scan -l domains.txt
```

Save JSON Lines output and reduce the number of simultaneous checks:

```sh
./abigail scan -l domains.txt --format jsonl -o results.jsonl --concurrency 10
```

Pipe a list from another tool or include lower-confidence edge-case rules:

```sh
cat domains.txt | ./abigail scan -l - --include-edge-cases
```

Use a different rule file or timeout:

```sh
./abigail scan -d sub.example.com --rules rules/providers.json --timeout 8s
```

For full CNAME-chain and NXDOMAIN evidence, specify a DNS resolver you are
authorized to use:

```sh
./abigail scan -d sub.example.com --resolver 1.1.1.1
```

An IP address or `IP:port` is accepted. Without `--resolver`, Abigail uses
your operating system's DNS configuration, which is often the right choice for
private or VPN-only hostnames.

Run `./abigail scan --help` for the exact options and defaults in your build.

### Scan options

| Option | Purpose | Default |
| --- | --- | --- |
| `-d`, `--domain` | Scan one hostname. | Required unless `-l` is used. |
| `-l`, `--list` | Scan one hostname per line from a file; `-` reads standard input. | Required unless `-d` is used. |
| `-o`, `--output` | Write output to a file, replacing it only after a completed scan. | Standard output. |
| `--format` | `text` or `jsonl`. | `text` |
| `--rules` | Use a custom JSON rule file. | Embedded rules. |
| `--resolver` | Query an explicit DNS server at `IP[:port]` for full CNAME-chain checks. | Operating system resolver. |
| `--concurrency` | Maximum simultaneous hostname checks, from 1 to 256. | 20 |
| `--rate` | Maximum new hostname checks per second; `0` disables pacing. | 20 |
| `--timeout` | Timeout for an individual DNS or HTTP request. | `5s` |
| `--include-edge-cases` | Include rules classified as edge cases. | Off. |

The scanner accepts ASCII/Punycode hostnames, removes duplicate entries from
lists, and ignores blank lines and lines beginning with `#`. It does not
accept URLs with `http://` or a path; supply the hostname only. `-d` and `-l`
are mutually exclusive.

### In Portuguese

No macOS ou Linux, instale o Go, execute `go build -o abigail ./cmd/abigail`
na pasta do projeto e depois `./abigail scan -d sub.seudominio.com`. Para
uma lista, use `-l domains.txt`, com um domínio por linha. Escaneie apenas
ativos seus ou para os quais você recebeu autorização.

## Reading results

Abigail reports evidence, not a guarantee that someone can take control of a
hostname. A matching DNS record and an error page can indicate a missing
provider resource; some providers prevent another account from claiming that
resource. A failed lookup or timeout is **unknown**, not proof that a hostname
is safe or vulnerable. Review the reported evidence and the provider's current
ownership rules before acting on a finding.

| Status | Meaning |
| --- | --- |
| `candidate` | DNS and the rule's HTTP or NXDOMAIN evidence matched. Claimability still needs independent confirmation. |
| `edge_case` | An opted-in rule for a provider with conditional or uncertain claimability matched. |
| `clean` | No bundled rule matched the available evidence. This is not a guarantee of safety. |
| `unknown` | A DNS or HTTP check could not finish reliably; inspect the reported error. |

JSON Lines writes one JSON object per checked hostname. This format works well
with `jq`, log processors, and CI systems. Keep scan output private when it
contains internal hostnames or infrastructure details.

Text output prints findings and unknown checks; the summary is written to
standard error. JSON Lines includes every checked hostname, including
`clean` results. Exit code `0` means no findings or unknown checks. Exit code
`1` means at least one finding and no unknown checks. Exit code `2` means at
least one check was unknown, the input was invalid, or the command could not
complete; it takes precedence over findings. A finding therefore makes a CI
step fail unless the caller handles exit code `1` deliberately.

## How detection works

1. Abigail resolves the supplied hostname and records DNS evidence. By
   default it uses the operating system's resolver, including local VPN DNS
   settings; this mode supplies the final canonical name. With `--resolver`,
   Abigail queries the specified DNS server directly and can inspect the full
   CNAME chain and NXDOMAIN responses.
2. It selects provider rules that match DNS evidence.
3. For a candidate, it requests the hostname over HTTPS when the rule needs
   a response status or body fingerprint. If HTTPS fails, it retries over
   HTTP and records which URL supplied the evidence. TLS certificate checks
   remain enabled; redirects are not followed.
4. It reports the evidence and the highest justified outcome. Missing or
   contradictory evidence is reported explicitly.

The current default pack contains 49 rules embedded in the executable; their
source lives in [`rules/`](rules/). They are part of the versioned project so a
scan can be reproduced with the same source revision. See the
[rule schema](rules/SCHEMA.md) for match semantics and the [attribution
notice](rules/NOTICE.md) for third-party rule data and its licenses.

## Responsible use

Use Abigail only on systems you own or have explicit authorization to assess.
It generates DNS and potentially HTTP traffic to the supplied hostnames.
Choose a concurrency level appropriate for the target and your authorization.

The maintainers and contributors are **not responsible for misuse**, damage,
or unauthorized activity performed with this software. The software is
provided **as is**, without warranty, as detailed in the [MIT license](LICENSE).
Nothing in a detection result grants permission to claim a resource or access
someone else's data.

## Development

```sh
go test ./...
go vet ./...
```

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for rule and
test expectations, and [SECURITY.md](SECURITY.md) for private vulnerability
reporting. The [accuracy protocol](docs/ACCURACY.md) describes reproducible
comparison with other scanners.

## License

Abigail's program code is released under the [MIT License](LICENSE). Adapted
rule data has separate attribution requirements described in
[rules/NOTICE.md](rules/NOTICE.md).
