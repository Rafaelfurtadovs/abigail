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

**Version note:** `v0.2.0` is the current release. Check `abigail version`
to identify the version you are running. The earlier `v0.1.0` release had a
smaller rule pack and no direct provider validation.

| Version | Rules | Edge-case rules by default | Direct provider validation |
| --- | ---: | --- | --- |
| Earlier `v0.1.0` | 49 | Off | No |
| Current `v0.2.0` | 97 mapped service identities | On; use `--exclude-edge-cases` to disable | Opt-in `--validate` for supported AWS/Azure names |

The examples below describe `v0.2.0`. Service count parity with another
scanner is not evidence of equal or better detection accuracy. See the
[changelog](CHANGELOG.md) for release changes.

## Features

- Scan one hostname or a line-delimited file of hostnames.
- Resolve CNAME, A, AAAA, and relevant NS records. When the DNS route is known,
  inspect the full CNAME chain and NXDOMAIN responses.
- Use versioned, reviewable provider rules embedded in the executable rather
  than an unpinned runtime download.
- Separate positive matches from unknown or incomplete checks.
- Write machine-readable JSON Lines output for CI or further analysis.
- Bound concurrency and per-host timeouts.
- Optionally ask supported AWS and Azure availability APIs about a matched
  resource name, without creating or claiming it.

## Requirements

- macOS or Linux, on a platform supported by the installed Go toolchain.
- Go 1.26.10 or newer to build `v0.2.0` or the current source, as specified by
  [`go.mod`](go.mod). The published release archives do not require Go.
- Network access for DNS lookups and, when a rule requires it, HTTP(S) checks.
  The optional `--validate` mode also needs access to the relevant AWS or
  Azure API and appropriately scoped credentials.

No administrator privileges are required. Run Abigail as an ordinary user.

## Download a release without Go

Download the archive for your system and `SHA256SUMS` from the
[v0.2.0 release](https://github.com/Rafaelfurtadovs/abigail/releases/tag/v0.2.0):

| System | Archive |
| --- | --- |
| macOS, Apple Silicon | `abigail_v0.2.0_darwin_arm64.tar.gz` |
| macOS, Intel | `abigail_v0.2.0_darwin_amd64.tar.gz` |
| Linux, x86-64 | `abigail_v0.2.0_linux_amd64.tar.gz` |
| Linux, ARM64 | `abigail_v0.2.0_linux_arm64.tar.gz` |

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

You can also install the published `v0.2.0` module with:

```sh
go install github.com/Rafaelfurtadovs/abigail/cmd/abigail@v0.2.0
```

Go places the command in `GOBIN` when set, otherwise in `$(go env GOPATH)/bin`.
Add that directory to your `PATH` to invoke `abigail` without `./`.
`@latest` follows the latest tagged release; it does not select unreleased
changes on the default branch.

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

The examples below use `v0.2.0`. For the earlier `v0.1.0` release, use
`./abigail scan --help` to see its available flags.

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

Pipe a list from another tool, excluding lower-confidence edge-case rules:

```sh
cat domains.txt | ./abigail scan -l - --exclude-edge-cases
```

Use a different rule file or timeout:

```sh
./abigail scan -d sub.example.com --rules rules/providers.json --timeout 8s
```

To choose a DNS resolver explicitly, for example when the system DNS route is
ambiguous, use:

```sh
./abigail scan -d sub.example.com --resolver 1.1.1.1
```

An IP address or `IP:port` is accepted. Without `--resolver`, Abigail inspects
the operating system's DNS configuration on macOS and Linux. When it can
identify the route unambiguously, it queries those servers directly and
records the full CNAME chain. When it cannot, it falls back to the system
resolver and marks the chain incomplete. The fallback preserves local or VPN
DNS behavior, but some NXDOMAIN-based findings then remain unknown.

`--resolver` affects **DNS evidence only**. HTTP(S) requests still use the
operating system's name resolution. In a split-DNS or VPN environment, the two
routes can see different records or reach different servers. For a meaningful
result, use a resolver consistent with the HTTP network view and review the
reported DNS chain and URL together.

In `v0.2.0`, request provider-side name availability
checks for supported AWS and Azure targets only after a signature matches:

```sh
./abigail scan -d sub.example.com --validate --format jsonl
```

For Azure App Service or Traffic Manager, provide a subscription ID through
`AZURE_SUBSCRIPTION_ID` or `--azure-subscription`, and authenticate through a
noninteractive credential source supported by the Azure SDK:

```sh
AZURE_SUBSCRIPTION_ID=00000000-0000-0000-0000-000000000000 \
  ./abigail scan -d sub.example.com --validate --format jsonl
```

The zero UUID is a placeholder; replace it with a subscription you are
authorized to use. AWS Elastic Beanstalk validation uses the AWS SDK's default
credential chain. Abigail does not open an interactive login or create a
provider resource. Without `--validate`, it does not request cloud credentials.

Run `./abigail scan --help` for the exact options and defaults in your build.

### Scan options

| Option | Purpose | Default |
| --- | --- | --- |
| `-d`, `--domain` | Scan one hostname. | Required unless `-l` is used. |
| `-l`, `--list` | Scan one hostname per line from a file; `-` reads standard input. | Required unless `-d` is used. |
| `-o`, `--output` | Write output to a file, replacing it only after a completed scan. | Standard output. |
| `--format` | `text` or `jsonl`. | `text` |
| `--rules` | Use a custom JSON rule file. | Embedded rules. |
| `--resolver` | Query an explicit DNS server at `IP[:port]` for full CNAME-chain checks. | Auto-detect the system DNS route, with a cautious fallback. |
| `--concurrency` | Maximum simultaneous hostname checks, from 1 to 256. | 20 |
| `--rate` | Maximum new hostname checks per second; `0` disables pacing. | 20 |
| `--timeout` | Timeout for an individual DNS or HTTP request. | `5s` |
| `--include-edge-cases` | Retained compatibility flag to include edge-case rules. | On in `v0.2.0`; off in `v0.1.0`. |
| `--exclude-edge-cases` | Exclude lower-confidence edge-case rules. | Off in `v0.2.0`; absent in `v0.1.0`. |
| `--validate` | Ask supported provider APIs whether a matched resource name is available. | Off. |
| `--azure-subscription` | Azure subscription ID for `--validate`; `AZURE_SUBSCRIPTION_ID` is also accepted. | Environment value, if set. |

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
| `validated` | A candidate signature matched and a supported provider API reported the exact resource name available. This does not prove exploitability. |
| `candidate` | DNS and the rule's HTTP or NXDOMAIN evidence matched. Claimability still needs independent confirmation. |
| `edge_case` | A lower-confidence rule for a provider with conditional or uncertain claimability matched. |
| `dismissed` | A signature matched, but a supported provider API reported the matched name unavailable. Review the JSONL `dismissed` evidence. |
| `clean` | No bundled rule matched the available evidence. This is not a guarantee of safety. |
| `unknown` | A DNS or HTTP check could not finish reliably; inspect the reported error. |

With `--validate`, each matched finding carries a `validation.state` in JSONL:
`available`, `unavailable`, `unknown`, or `unsupported`. `available` upgrades a
regular candidate to `validated`. `unavailable` moves it to the JSONL
`dismissed` list, yielding overall `dismissed` when no active finding remains.
`unknown` and `unsupported` leave the original alert in place.
Lower-confidence `edge_case` rules are never upgraded to `validated`.
The API check does not establish that a provider will permit ownership or
content control of the hostname.

For the DigitalOcean NS rule, Abigail can report an `edge_case` with
`delegation_unresolved: true` when it verifies an exact NS delegation at the
parent authority but cannot complete the delegated child lookup. This is
**not** an observed NXDOMAIN or a confirmed takeover; the finding has
no `target_nxdomain` evidence and needs separate investigation.

Direct validation requires a complete CNAME chain and a rule match on the
**exact final CNAME target**. The provider API response must refer to that
same target; an earlier CNAME hop cannot be used to validate a different
resource. Validation currently supports regional AWS Elastic Beanstalk names
and Azure App Service or Traffic Manager names. Legacy or generated Beanstalk
aliases, Azure CDN and other Azure resource families, and all other providers
remain unsupported by direct validation. A missing subscription, missing
credentials, API error, or inconclusive response yields `unknown`, not a
negative result.

JSON Lines writes one JSON object per checked hostname. This format works well
with `jq`, log processors, and CI systems. Keep scan output private when it
contains internal hostnames or infrastructure details.

In `v0.2.0`, `http_probes` records separate HTTPS and HTTP results,
including each URL, status, character encoding, truncation, or error. The
finding's `http_url` identifies the response that matched its rule. If one
scheme fails and neither response matches, the scan is `unknown` rather than
`clean`; a match from either scheme can still produce a finding.

Text output prints findings, unknown checks, and checks where all findings
were dismissed; the summary is written to standard error. JSON Lines includes
every checked hostname, including `clean` results. Exit code `0` means no
active findings or unknown checks; a fully `dismissed` scan also exits `0`.
Exit code `1` means at least one finding and no unknown checks. Exit code `2`
means at least one check was unknown, the input was invalid, or the command could not
complete; it takes precedence over findings. A finding therefore makes a CI
step fail unless the caller handles exit code `1` deliberately.

## How detection works

1. Abigail resolves the supplied hostname and records DNS evidence. On macOS
   and Linux, it first attempts to identify the system's DNS route and query
   those servers directly for the full CNAME chain. If the route is ambiguous,
   it uses the system resolver and marks the chain incomplete. `--resolver`
   selects a DNS server explicitly.
2. It selects provider rules that match DNS evidence.
3. For a candidate, it requests the hostname over HTTPS **and** HTTP when a
   rule needs a response status or body fingerprint. It checks each response
   independently and records both in `http_probes`. TLS certificate checks
   remain enabled; redirects are not followed.
4. If `--validate` is set and a signature matches the exact final CNAME target,
   Abigail checks that target's name availability through a supported provider
   API. It never creates a resource.
5. It reports the evidence and the highest justified outcome. Missing or
   contradictory evidence is reported explicitly.

The `v0.2.0` pack contains 97 rules (61 with `vulnerable` status
and 36 lower-confidence `edge_case`) embedded in the executable; their
source lives in [`rules/`](rules/). They are part of the versioned project so a
scan can be reproduced with the same source revision. See the
[rule schema](rules/SCHEMA.md) for match semantics and the [attribution
notice](rules/NOTICE.md) for third-party rule data and its licenses. The
[coverage inventory](docs/RULE_COVERAGE.md) explains which service families
are mapped and which are still uncertain. Matching the count of services in a
reference catalog does not establish equal detection accuracy or provider
claimability.

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
