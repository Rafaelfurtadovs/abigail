# Rule coverage and quality review

Abigail's reference inventory is the 97 effective service identities loaded by
[Subdominator commit `9f9dfa0`](https://github.com/Stratus-Security/Subdominator/tree/9f9dfa0383de9ca786a118b8a01d3570cfe5bbd0),
including entries from [can-i-take-over-xyz commit `5bd4e12`](https://github.com/EdOverflow/can-i-take-over-xyz/tree/5bd4e12837911c8475486f1da922c9b9c706e632).
Version `v0.2.0` mapped all 97 to active rules. In `v0.2.1`, the pack has
**53 active rules and 44 excluded historical identities**. The full
[machine-readable inventory](../rules/coverage.json) records every identity,
active rule, exclusion decision, and reason. A lower rule count is a deliberate
precision choice; it is not proof of better real-world accuracy.

The audit asked whether each DNS selector points to the provider's current
custom-domain route, whether its HTTP or NXDOMAIN evidence distinguishes a
missing resource from a working or suspended one, whether a different account
can plausibly claim the name, and whether the source supports the current
behavior. A provider error page alone never proves claimability. The 53 active
rules contain 25 categorized `vulnerable` and 28 lower-confidence
`edge_case` entries. Of those, 48 require HTTP body evidence, five use
NXDOMAIN, and **none** accepts HTTP status alone.

## Excluded entries

The following table lists **all 44 excluded rule IDs**. Exclusion means the
previous signature is too weak for an active takeover alert; it does not mean
every hostname using that provider is safe.

| Reason | Excluded rule IDs |
| --- | --- |
| Generic HTTP status only (10): a 301, 302, 400, 403, 404, or 500 does not identify an unassigned resource. | `better-uptime`, `bubble-io`, `getcloudapp`, `helprace`, `launchrock`, `meteor-cloud-galaxy`, `softr`, `useresponse`, `zoho-forms`, `zoho-forms-india` |
| Reference catalog says `Not vulnerable` (6); no current controlled evidence justifies overriding it. | `acquia`, `fastly`, `instapage`, `unbounce`, `uservoice`, `zendesk` |
| An owned but inactive, unpaid, unpublished, or otherwise non-claimable resource can produce the fingerprint, or the documented target has changed (13). | `activecampaign`, `airee-ru`, `appery-io`, `branch-io`, `convertkit`, `jazzhr`, `ngrok`, `readme-io`, `shopify`, `thinkific`, `tilda`, `uptimerobot`, `vercel` |
| Unsupported or invalid custom-domain route (2): the old signature does not point to a documented claimable custom-domain target. | `bitbucket`, `brightcove` |
| Generic or unrelated body text (9): the response does not establish that the provider resource is free. | `datocms-com`, `flexbe`, `gemfury`, `getresponse`, `pagewiz`, `smartjobboard`, `strikingly`, `surveygizmo`, `tave` |
| Shared or stale NXDOMAIN target (3): missing shared ingress or old trial DNS does not identify a claimable customer site. | `discourse`, `refined`, `smugsmug` |
| Discontinued service (1): the old signature cannot justify a current takeover alert. | `tictail` |

Selected provider counterexamples informed these decisions: [Shopify stores
can be deactivated and later reactivated](https://help.shopify.com/en/manual/your-account/manage-orgs-and-stores/manage-pricing-plan/deactivate-store),
[Tilda disconnects custom domains when a subscription expires while retaining
projects](https://help.tilda.cc/subscription),
[Branch documents missing links on domains managed by an existing account](https://help.branch.io/account-hub/basic-link-configuration),
[Vercel's `DEPLOYMENT_NOT_FOUND` means the deployment is missing](https://vercel.com/docs/errors/deployment_not_found),
and [Zendesk help centers can be closed and reopened](https://support.zendesk.com/hc/en-us/articles/4408829088026-Deactivating-your-help-center).
For `bitbucket`, [Atlassian's website publishing guide](https://support.atlassian.com/bitbucket-cloud/docs/publishing-a-website-on-bitbucket-cloud/)
uses `<workspaceid>.bitbucket.io`, and an [accepted Atlassian Community answer](https://community.atlassian.com/forums/discussion/855794/whats-bitbucket-ios-ip-address-for-page-hosting-on-custom-url)
states that a custom hostname is unavailable. For `brightcove`,
[Brightcove's custom-domain instructions](https://gallery.support.brightcove.com/settings/configuring-custom-domains-and-ssl.html)
identify `brightcovegallery.com`, `gallery.video`, and `bcvp0rtal.com` as
provider-owned site domains; a publisher's custom domain instead uses a
separate CNAME value shown in the account settings, such as a CloudFront
hostname. The old DNS selectors therefore did not identify the documented
custom-domain route.
The [reference catalog](https://github.com/EdOverflow/can-i-take-over-xyz/blob/5bd4e12837911c8475486f1da922c9b9c706e632/fingerprints.json)
supplies the six `Not vulnerable` classifications. Current
[Discourse custom-domain instructions](https://meta.discourse.org/t/configure-your-domain-name-for-hosted-discourse/21827)
and [Refined's custom-domain instructions](https://www.refined.com/blog/boost-adoption-with-custom-domains-on-refined-sites-for-jsm)
also differ from the old NXDOMAIN assumptions. Former integration partner
[Printful reports that Tictail has been inactive since April 2019](https://www.printful.com/news/printful-announces-its-integration-with-popular-ecommerce-platform-tictail).
The exclusions are reversible
when a provider-specific positive fixture, negative fixture, and ownership
evidence justify a new rule.

## Stronger active selectors

- **AWS S3:** [AWS documents regional REST and website CNAMEs and explicitly
  warns that another AWS account can create a missing matching
  bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/VirtualHosting.html).
  Abigail now recognizes regional and website endpoints and requires HTTP 404
  plus `NoSuchBucket`, the [specific S3 error code](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/ErrorResponses.html),
  instead of a loose English phrase.
- **AWS Elastic Beanstalk:** the NXDOMAIN rule now accepts regional CNAMEs
  whose exact name can be checked by
  [CheckDNSAvailability](https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_CheckDNSAvailability.html).
  Legacy or generated aliases without that exact-name check remain outside
  this signature.
- **Amazon Cognito:** only the documented `<prefix>.auth[(-fips)].<region>.amazoncognito.com`
  shape matches. The optional read-only
  [DescribeUserPoolDomain API](https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_DescribeUserPoolDomain.html)
  can dismiss an alert when that exact prefix is already assigned. A missing
  prefix remains inconclusive, never `validated`.
- **Microsoft Azure:** the former 16-suffix vulnerable rule is now a narrower
  `edge_case` over current resource shapes from
  [Microsoft's dangling DNS guidance](https://learn.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover).
  It excludes secure unique App Service hostnames, which
  [Microsoft says prevent cross-organization reuse](https://learn.microsoft.com/en-us/azure/app-service/reference-dangling-subdomain-prevention),
  and removes obsolete or misattributed suffixes. Azure's availability APIs
  remain optional and cannot by themselves establish control of a custom
  domain protected by `asuid` TXT.
- **DigitalOcean:** the NS rule now accepts only the provider's
  [three published nameservers](https://docs.digitalocean.com/products/networking/dns/details/features/).
  A parent-authoritative delegation with unresolved child DNS is reported as
  `delegation_unresolved` and remains an `edge_case`, not a confirmed takeover.
- **Surge:** the active rule includes the current `geo.surge.world` CNAME,
  documented A record, and older CNAME targets from
  [Surge's custom-domain guide](https://surge.sh/docs/platform/custom-domains).
- **Read the Docs:** the Community rule now requires the exact
  `readthedocs.io` CNAME from its
  [custom-domain guide](https://docs.readthedocs.com/platform/stable/guides/custom-domains.html).
  A CNAME to `<project>.readthedocs.io` is not the documented custom-domain
  route. Business hosting uses `<hash>.domains.readthedocs.com`; that route is
  a documented coverage gap until a distinguishing fingerprint is verified.
- **Cargo:** the retained rule covers legacy `cargocollective.com` targets.
  [Cargo 3 documents](https://docs.cargo.site/domains-purchased-elsewhere)
  `subdomain.cargo.site` for custom subdomains. That current route remains a
  coverage gap until its missing-site response and claimability can be
  distinguished from an owned site.
- **Worksites:** the only public
  [takeover proof](https://github.com/EdOverflow/can-i-take-over-xyz/issues/142)
  found is from 2020. The fingerprint remains for historical coverage, but is
  now an `edge_case` until current registration behavior is reconfirmed.

DNS suffix matchers now require a child label; use an exact matcher for a valid
bare provider hostname. NXDOMAIN can support a CNAME rule only when the
**final** CNAME target itself matches that rule. The parser rejects rules based
only on an HTTP status. These checks guard against false-positive cases found
in the audit, with focused regression fixtures in `rules/quality_test.go` and
`internal/scanner/scanner_test.go`.

These changes have not been evaluated against a labeled real-world corpus.
Use the [accuracy protocol](ACCURACY.md) before claiming higher precision,
recall, or overall superiority to another scanner. Record exclusions as
coverage gaps in any comparison rather than counting them as negatives.
