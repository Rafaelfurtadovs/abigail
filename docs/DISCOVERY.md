# Subdomain discovery

`abigail scan -d example.com` discovers subdomains, then checks the discovered
names **and the root** for potential takeovers. By default, Abigail queries
multiple passive sources, including [crt.name](https://crt.name/). It filters
invalid and out-of-scope names and removes duplicates before scanning. Passive
discovery does not discard unresolved names, since dangling DNS records can
matter for takeover checks.

```sh
abigail scan -d example.com
abigail scan -l roots.txt
```

Put one root domain per line in `roots.txt`. Discovery rejects a root that is
only a public suffix, such as `com.br`. Roots in a list are processed
sequentially with a shared provider rate limiter, so request pacing continues
across the list. Provider quotas can still be reached across a large list;
Abigail reports source warnings.
The default text output prints `[clean] hostname` for a checked name with no
matching takeover signature, so the output shows which names were checked even
when no finding is reported.

To inspect the child names without takeover checks, use:

```sh
abigail scan -d example.com --discover-only
abigail scan -d example.com --discover-only --format jsonl -o names.jsonl
```

Discovery-only output excludes the root. Its JSONL records look like
`{"domain":"www.example.com","status":"discovered"}`; `discovered` is not
a takeover verdict.

To scan only the supplied hostname or an existing list of hostnames, use
`--no-discover`:

```sh
abigail scan -d app.example.com --no-discover
abigail scan -l hosts.txt --no-discover
```

`--native-discovery` uses Abigail's direct implementations of
[crt.name](https://crt.name/), [crt.sh](https://crt.sh/),
[Cert Spotter](https://sslmate.com/help/reference/ct_search_api_v1), and
[HackerTarget](https://hackertarget.com/find-dns-host-records/) in place of the
default passive engine. This is useful if you want to use those four sources
alone.

`--brute` also tries a bounded built-in DNS wordlist with either passive mode.
It makes live DNS queries and filters answers that appear to come from wildcard
DNS:

```sh
abigail scan -d example.com --brute
```

No API key is needed for the basic public sources. Optional API keys enable
additional providers. Abigail looks for `provider-config.yaml` in
`~/Library/Application Support/abigail/` on macOS and
`$XDG_CONFIG_HOME/abigail/` (or `~/.config/abigail/`) on Linux. Override the
location with `ABIGAIL_PROVIDER_CONFIG` or
`--provider-config path/to/provider-config.yaml`. An existing provider YAML
from another tool can be reused with the flag; Abigail does not load another
app's config automatically. Before discovery it checks that the file is a
readable YAML mapping, without printing parse details that could contain a
secret. In native mode, direct
Cert Spotter and HackerTarget queries accept `CERTSPOTTER_API_KEY` and
`HACKERTARGET_API_KEY`, respectively.

Each passive source has a total deadline of 10 minutes by default; change it
with `--discovery-timeout 2m`. In native mode, direct HTTP requests have a
separate limit of 30 seconds each (or the shorter discovery deadline).
`--timeout` controls the later DNS and HTTP takeover checks. The default run
limit is 50,000 unique hostnames, including roots. Raise it with
`--max-hosts 100000` for a larger authorized scope. The accepted range is
1 to 100,000. The default passive engine applies the same value as a limit
**per source** and limits each passive HTTP response body to 32 MiB. Large
responses or sources that reach a limit can produce partial results and
warnings.

Discovery depends on third-party indexes and their availability, quotas, and
credentials. [crt.name](https://crt.name/) accepts registrable apex domains
and allows 100 free queries per IP per day; its historical records need not
resolve today. [HackerTarget](https://hackertarget.com/find-dns-host-records/)
limits free responses to 50 rows and 20 queries per day. In native mode,
Abigail warns when a response may be truncated.
[Cert Spotter](https://sslmate.com/help/reference/ct_search_api_v1) restricts
unauthenticated use. Abigail's native pagination continues until an empty page
or the source deadline and reports partial results if a later page fails.
Other sources may also need keys or hit provider limits. Source failures are
reported; if every enabled source fails without returning valid names, Abigail
stops instead of presenting a one-host scan as complete. The number of names
found varies with configuration, response timing, and provider data.

Abigail uses normal HTTPS certificate verification, blocks redirects
to another origin where credentials could be forwarded, and avoids printing
credential-bearing request URLs or response bodies in errors. The Chaos
adapter uses that same HTTP session. See the
[third-party licenses](../THIRD_PARTY_NOTICES.md).

A discovered name is **not** a takeover finding. A matching takeover signature
is a lead that requires separate confirmation of provider ownership and
claimability. Use Abigail only on domains you own or are authorized to assess.
