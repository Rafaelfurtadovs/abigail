# Dependency licenses

This inventory covers the union of external Go modules compiled into Abigail's
macOS and Linux release binaries (`amd64` and `arm64`, `CGO_ENABLED=0`).
Exact upstream license and notice files are copied below without modification.
Regenerate with `python3 scripts/generate_licenses.py`; verify with
`python3 scripts/generate_licenses.py --check`.

The Go standard library (`go1.26.10`) license and patent notice: [LICENSE](go/go1.26.10/LICENSE), [PATENTS](go/go1.26.10/PATENTS).
The modified vendored Subfinder code and its upstream MIT notice are
documented in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

| Module | Version | Upstream license / notice files |
| --- | --- | --- |
| `aead.dev/minisign` | `v0.2.0` | [LICENSE](modules/aead.dev/minisign@v0.2.0/LICENSE) |
| `github.com/Azure/azure-sdk-for-go/sdk/azcore` | `v1.23.3` | [LICENSE.txt](modules/github.com/Azure/azure-sdk-for-go/sdk/azcore@v1.23.3/LICENSE.txt) |
| `github.com/Azure/azure-sdk-for-go/sdk/azidentity` | `v1.15.0` | [LICENSE.txt](modules/github.com/Azure/azure-sdk-for-go/sdk/azidentity@v1.15.0/LICENSE.txt) |
| `github.com/Azure/azure-sdk-for-go/sdk/internal` | `v1.13.0` | [LICENSE.txt](modules/github.com/Azure/azure-sdk-for-go/sdk/internal@v1.13.0/LICENSE.txt) |
| `github.com/AzureAD/microsoft-authentication-library-for-go` | `v1.10.1` | [LICENSE](modules/github.com/AzureAD/microsoft-authentication-library-for-go@v1.10.1/LICENSE) |
| `github.com/Masterminds/semver/v3` | `v3.2.1` | [LICENSE.txt](modules/github.com/Masterminds/semver/v3@v3.2.1/LICENSE.txt) |
| `github.com/VividCortex/ewma` | `v1.2.0` | [LICENSE](modules/github.com/VividCortex/ewma@v1.2.0/LICENSE) |
| `github.com/alecthomas/chroma/v2` | `v2.14.0` | [COPYING](modules/github.com/alecthomas/chroma/v2@v2.14.0/COPYING) |
| `github.com/asaskevich/govalidator` | `v0.0.0-20230301143203-a9d515a09cc2` | [LICENSE](modules/github.com/asaskevich/govalidator@v0.0.0-20230301143203-a9d515a09cc2/LICENSE) |
| `github.com/aws/aws-sdk-go-v2` | `v1.47.5` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2@v1.47.5/LICENSE.txt), [NOTICE.txt](modules/github.com/aws/aws-sdk-go-v2@v1.47.5/NOTICE.txt) |
| `github.com/aws/aws-sdk-go-v2/config` | `v1.33.13` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/config@v1.33.13/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/credentials` | `v1.20.13` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/credentials@v1.20.13/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/feature/ec2/imds` | `v1.20.5` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/feature/ec2/imds@v1.20.5/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/internal/configsources` | `v1.5.8` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/internal/configsources@v1.5.8/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/internal/endpoints/v2` | `v2.8.8` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/internal/endpoints/v2@v2.8.8/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/internal/v4a` | `v1.5.8` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/internal/v4a@v1.5.8/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider` | `v1.75.7` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider@v1.75.7/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk` | `v1.43.6` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk@v1.43.6/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding` | `v1.13.23` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding@v1.13.23/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/service/internal/presigned-url` | `v1.14.8` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/service/internal/presigned-url@v1.14.8/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/service/signin` | `v1.12.1` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/service/signin@v1.12.1/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/service/sso` | `v1.39.1` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/service/sso@v1.39.1/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/service/ssooidc` | `v1.44.1` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/service/ssooidc@v1.44.1/LICENSE.txt) |
| `github.com/aws/aws-sdk-go-v2/service/sts` | `v1.51.6` | [LICENSE.txt](modules/github.com/aws/aws-sdk-go-v2/service/sts@v1.51.6/LICENSE.txt) |
| `github.com/aws/smithy-go` | `v1.28.7` | [LICENSE](modules/github.com/aws/smithy-go@v1.28.7/LICENSE), [NOTICE](modules/github.com/aws/smithy-go@v1.28.7/NOTICE) |
| `github.com/aymanbagabas/go-osc52/v2` | `v2.0.1` | [LICENSE](modules/github.com/aymanbagabas/go-osc52/v2@v2.0.1/LICENSE) |
| `github.com/aymerick/douceur` | `v0.2.0` | [LICENSE](modules/github.com/aymerick/douceur@v0.2.0/LICENSE) |
| `github.com/charmbracelet/glamour` | `v0.8.0` | [LICENSE](modules/github.com/charmbracelet/glamour@v0.8.0/LICENSE) |
| `github.com/charmbracelet/lipgloss` | `v0.13.0` | [LICENSE](modules/github.com/charmbracelet/lipgloss@v0.13.0/LICENSE) |
| `github.com/charmbracelet/x/ansi` | `v0.3.2` | [LICENSE](modules/github.com/charmbracelet/x/ansi@v0.3.2/LICENSE) |
| `github.com/cheggaaa/pb/v3` | `v3.1.4` | [LICENSE](modules/github.com/cheggaaa/pb/v3@v3.1.4/LICENSE) |
| `github.com/cnf/structhash` | `v0.0.0-20250313080605-df4c6cc74a9a` | [LICENSE](modules/github.com/cnf/structhash@v0.0.0-20250313080605-df4c6cc74a9a/LICENSE) |
| `github.com/corpix/uarand` | `v0.2.0` | [license](modules/github.com/corpix/uarand@v0.2.0/license) |
| `github.com/djherbis/times` | `v1.6.0` | [LICENSE](modules/github.com/djherbis/times@v1.6.0/LICENSE) |
| `github.com/dlclark/regexp2` | `v1.11.5` | [LICENSE](modules/github.com/dlclark/regexp2@v1.11.5/LICENSE) |
| `github.com/ebitengine/purego` | `v0.10.0` | [LICENSE](modules/github.com/ebitengine/purego@v0.10.0/LICENSE) |
| `github.com/fatih/color` | `v1.15.0` | [LICENSE.md](modules/github.com/fatih/color@v1.15.0/LICENSE.md) |
| `github.com/gaissmai/bart` | `v0.29.1` | [LICENSE](modules/github.com/gaissmai/bart@v0.29.1/LICENSE) |
| `github.com/golang-jwt/jwt/v5` | `v5.3.1` | [LICENSE](modules/github.com/golang-jwt/jwt/v5@v5.3.1/LICENSE) |
| `github.com/google/go-github/v92` | `v92.0.0` | [LICENSE](modules/github.com/google/go-github/v92@v92.0.0/LICENSE) |
| `github.com/google/go-querystring` | `v1.2.0` | [LICENSE](modules/github.com/google/go-querystring@v1.2.0/LICENSE) |
| `github.com/google/shlex` | `v0.0.0-20191202100458-e7afc7fbc510` | [COPYING](modules/github.com/google/shlex@v0.0.0-20191202100458-e7afc7fbc510/COPYING) |
| `github.com/google/uuid` | `v1.6.0` | [LICENSE](modules/github.com/google/uuid@v1.6.0/LICENSE) |
| `github.com/gorilla/css` | `v1.0.1` | [LICENSE](modules/github.com/gorilla/css@v1.0.1/LICENSE) |
| `github.com/hako/durafmt` | `v0.0.0-20210316092057-3a2c319c1acd` | [LICENSE](modules/github.com/hako/durafmt@v0.0.0-20210316092057-3a2c319c1acd/LICENSE) |
| `github.com/json-iterator/go` | `v1.1.12` | [LICENSE](modules/github.com/json-iterator/go@v1.1.12/LICENSE) |
| `github.com/kylelemons/godebug` | `v1.1.0` | [LICENSE](modules/github.com/kylelemons/godebug@v1.1.0/LICENSE) |
| `github.com/lib/pq` | `v1.10.9` | [LICENSE.md](modules/github.com/lib/pq@v1.10.9/LICENSE.md) |
| `github.com/logrusorgru/aurora/v4` | `v4.0.0` | [LICENSE](modules/github.com/logrusorgru/aurora/v4@v4.0.0/LICENSE) |
| `github.com/lucasb-eyer/go-colorful` | `v1.2.0` | [LICENSE](modules/github.com/lucasb-eyer/go-colorful@v1.2.0/LICENSE) |
| `github.com/mattn/go-colorable` | `v0.1.13` | [LICENSE](modules/github.com/mattn/go-colorable@v0.1.13/LICENSE) |
| `github.com/mattn/go-isatty` | `v0.0.20` | [LICENSE](modules/github.com/mattn/go-isatty@v0.0.20/LICENSE) |
| `github.com/mattn/go-runewidth` | `v0.0.16` | [LICENSE](modules/github.com/mattn/go-runewidth@v0.0.16/LICENSE) |
| `github.com/microcosm-cc/bluemonday` | `v1.0.27` | [LICENSE.md](modules/github.com/microcosm-cc/bluemonday@v1.0.27/LICENSE.md) |
| `github.com/miekg/dns` | `v1.1.73` | [LICENSE](modules/github.com/miekg/dns@v1.1.73/LICENSE) |
| `github.com/minio/selfupdate` | `v0.6.1-0.20230907112617-f11e74f84ca7` | [LICENSE](modules/github.com/minio/selfupdate@v0.6.1-0.20230907112617-f11e74f84ca7/LICENSE), [NOTICE](modules/github.com/minio/selfupdate@v0.6.1-0.20230907112617-f11e74f84ca7/NOTICE) |
| `github.com/modern-go/concurrent` | `v0.0.0-20180306012644-bacd9c7ef1dd` | [LICENSE](modules/github.com/modern-go/concurrent@v0.0.0-20180306012644-bacd9c7ef1dd/LICENSE) |
| `github.com/modern-go/reflect2` | `v1.0.2` | [LICENSE](modules/github.com/modern-go/reflect2@v1.0.2/LICENSE) |
| `github.com/muesli/reflow` | `v0.3.0` | [LICENSE](modules/github.com/muesli/reflow@v0.3.0/LICENSE) |
| `github.com/muesli/termenv` | `v0.15.3-0.20240618155329-98d742f6907a` | [LICENSE](modules/github.com/muesli/termenv@v0.15.3-0.20240618155329-98d742f6907a/LICENSE) |
| `github.com/pkg/browser` | `v0.0.0-20240102092130-5ac0b6a4141c` | [LICENSE](modules/github.com/pkg/browser@v0.0.0-20240102092130-5ac0b6a4141c/LICENSE) |
| `github.com/pkg/errors` | `v0.9.1` | [LICENSE](modules/github.com/pkg/errors@v0.9.1/LICENSE) |
| `github.com/projectdiscovery/blackrock` | `v0.0.2` | [LICENSE.md](modules/github.com/projectdiscovery/blackrock@v0.0.2/LICENSE.md) |
| `github.com/projectdiscovery/cdncheck` | `v1.3.1` | [LICENSE.md](modules/github.com/projectdiscovery/cdncheck@v1.3.1/LICENSE.md) |
| `github.com/projectdiscovery/dnsx` | `v1.3.1` | [LICENSE.md](modules/github.com/projectdiscovery/dnsx@v1.3.1/LICENSE.md) |
| `github.com/projectdiscovery/goflags` | `v0.2.1` | [LICENSE.md](modules/github.com/projectdiscovery/goflags@v0.2.1/LICENSE.md) |
| `github.com/projectdiscovery/gologger` | `v1.1.73` | [LICENSE.md](modules/github.com/projectdiscovery/gologger@v1.1.73/LICENSE.md) |
| `github.com/projectdiscovery/machineid` | `v0.0.0-20250715113114-c77eb3567582` | [LICENSE.md](modules/github.com/projectdiscovery/machineid@v0.0.0-20250715113114-c77eb3567582/LICENSE.md) |
| `github.com/projectdiscovery/ratelimit` | `v0.0.92` | [LICENSE](modules/github.com/projectdiscovery/ratelimit@v0.0.92/LICENSE) |
| `github.com/projectdiscovery/retryabledns` | `v1.0.116` | [LICENSE.md](modules/github.com/projectdiscovery/retryabledns@v1.0.116/LICENSE.md) |
| `github.com/projectdiscovery/utils` | `v0.11.6` | [LICENSE.md](modules/github.com/projectdiscovery/utils@v0.11.6/LICENSE.md) |
| `github.com/rivo/uniseg` | `v0.4.7` | [LICENSE.txt](modules/github.com/rivo/uniseg@v0.4.7/LICENSE.txt) |
| `github.com/rs/xid` | `v1.5.0` | [LICENSE](modules/github.com/rs/xid@v1.5.0/LICENSE) |
| `github.com/saintfish/chardet` | `v0.0.0-20230101081208-5e3ef4b5456d` | [LICENSE](modules/github.com/saintfish/chardet@v0.0.0-20230101081208-5e3ef4b5456d/LICENSE) |
| `github.com/shirou/gopsutil/v4` | `v4.26.3` | [LICENSE](modules/github.com/shirou/gopsutil/v4@v4.26.3/LICENSE) |
| `github.com/tidwall/gjson` | `v1.18.0` | [LICENSE](modules/github.com/tidwall/gjson@v1.18.0/LICENSE) |
| `github.com/tidwall/match` | `v1.2.0` | [LICENSE](modules/github.com/tidwall/match@v1.2.0/LICENSE) |
| `github.com/tidwall/pretty` | `v1.2.1` | [LICENSE](modules/github.com/tidwall/pretty@v1.2.1/LICENSE) |
| `github.com/tklauser/go-sysconf` | `v0.3.16` | [LICENSE](modules/github.com/tklauser/go-sysconf@v0.3.16/LICENSE) |
| `github.com/tklauser/numcpus` | `v0.11.0` | [LICENSE](modules/github.com/tklauser/numcpus@v0.11.0/LICENSE) |
| `github.com/tomnomnom/linkheader` | `v0.0.0-20180905144013-02ca5825eb80` | [LICENSE](modules/github.com/tomnomnom/linkheader@v0.0.0-20180905144013-02ca5825eb80/LICENSE) |
| `github.com/weppos/publicsuffix-go` | `v0.50.3` | [LICENSE.txt](modules/github.com/weppos/publicsuffix-go@v0.50.3/LICENSE.txt) |
| `github.com/yuin/goldmark` | `v1.7.17` | [LICENSE](modules/github.com/yuin/goldmark@v1.7.17/LICENSE) |
| `github.com/yuin/goldmark-emoji` | `v1.0.3` | [LICENSE](modules/github.com/yuin/goldmark-emoji@v1.0.3/LICENSE) |
| `github.com/zcalusic/sysinfo` | `v1.0.2` | [LICENSE](modules/github.com/zcalusic/sysinfo@v1.0.2/LICENSE) |
| `go.uber.org/multierr` | `v1.11.0` | [LICENSE.txt](modules/go.uber.org/multierr@v1.11.0/LICENSE.txt) |
| `golang.org/x/crypto` | `v0.58.1-0.20261009181718-2f1f834330b2` | [LICENSE](modules/golang.org/x/crypto@v0.58.1-0.20261009181718-2f1f834330b2/LICENSE) |
| `golang.org/x/exp` | `v0.0.0-20260112195511-716be5621a96` | [LICENSE](modules/golang.org/x/exp@v0.0.0-20260112195511-716be5621a96/LICENSE) |
| `golang.org/x/net` | `v0.62.0` | [LICENSE](modules/golang.org/x/net@v0.62.0/LICENSE) |
| `golang.org/x/oauth2` | `v0.27.0` | [LICENSE](modules/golang.org/x/oauth2@v0.27.0/LICENSE) |
| `golang.org/x/sync` | `v0.24.0` | [LICENSE](modules/golang.org/x/sync@v0.24.0/LICENSE) |
| `golang.org/x/sys` | `v0.49.0` | [LICENSE](modules/golang.org/x/sys@v0.49.0/LICENSE) |
| `golang.org/x/term` | `v0.47.0` | [LICENSE](modules/golang.org/x/term@v0.47.0/LICENSE) |
| `golang.org/x/text` | `v0.43.0` | [LICENSE](modules/golang.org/x/text@v0.43.0/LICENSE) |
| `golang.org/x/time` | `v0.5.0` | [LICENSE](modules/golang.org/x/time@v0.5.0/LICENSE) |
| `gopkg.in/yaml.v3` | `v3.0.1` | [LICENSE](modules/gopkg.in/yaml.v3@v3.0.1/LICENSE), [NOTICE](modules/gopkg.in/yaml.v3@v3.0.1/NOTICE) |
