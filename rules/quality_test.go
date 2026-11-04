package rules_test

import (
	"testing"

	"github.com/Rafaelfurtadovs/abigail/internal/ruleengine"
	"github.com/Rafaelfurtadovs/abigail/rules"
)

func auditedRule(t *testing.T, id string) ruleengine.Rule {
	t.Helper()
	pack, err := ruleengine.Parse(rules.Default)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range pack.Rules {
		if rule.ID == id {
			return rule
		}
	}
	t.Fatalf("missing audited rule %q", id)
	return ruleengine.Rule{}
}

func TestS3RegionalAndWebsiteEndpointsNeedNoSuchBucket(t *testing.T) {
	rule := auditedRule(t, "aws-s3")
	for _, target := range []string{
		"s3.amazonaws.com",
		"bucket.s3.amazonaws.com",
		"bucket.s3.us-east-1.amazonaws.com",
		"bucket.s3-eu-west-1.amazonaws.com",
		"sub.example.com.s3-website.us-west-2.amazonaws.com",
		"sub.example.com.s3-website-eu-west-1.amazonaws.com",
	} {
		if got := ruleengine.MatchDNS(rule, []string{target}, nil, nil, nil); len(got) == 0 {
			t.Errorf("official S3 target %q not covered", target)
		}
	}
	for _, target := range []string{"s3.amazonaws.com.attacker.test", "bucket.s3.not-a-region.amazonaws.com"} {
		if got := ruleengine.MatchDNS(rule, []string{target}, nil, nil, nil); len(got) != 0 {
			t.Errorf("unexpected S3 target match %q: %+v", target, got)
		}
	}
	for _, tc := range []struct {
		status int
		body   string
		want   bool
	}{
		{404, `<Error><Code>NoSuchBucket</Code></Error>`, true},
		{404, `<h3>Code: NoSuchBucket</h3>`, true},
		{404, `The specified bucket does not exist`, false},
		{404, `<Error><Code>NoSuchKey</Code></Error>`, false},
		{403, `<Error><Code>NoSuchBucket</Code></Error>`, false},
	} {
		_, got := ruleengine.MatchHTTP(rule, tc.status, []byte(tc.body))
		if got != tc.want {
			t.Errorf("status=%d body=%q: got %v, want %v", tc.status, tc.body, got, tc.want)
		}
	}
}

func TestCognitoOnlyMatchesDocumentedPrefixDomain(t *testing.T) {
	rule := auditedRule(t, "amazon-cognito")
	for _, target := range []string{"pool.auth.us-east-1.amazoncognito.com", "pool.auth-fips.us-gov-west-1.amazoncognito.com"} {
		if got := ruleengine.MatchDNS(rule, []string{target}, nil, nil, nil); len(got) != 1 {
			t.Errorf("expected Cognito prefix domain %q: %+v", target, got)
		}
	}
	for _, target := range []string{"amazoncognito.com", "other.amazoncognito.com", "pool.auth.bad.amazoncognito.com", "pool.auth.us-east-1.amazoncognito.com.attacker.test"} {
		if got := ruleengine.MatchDNS(rule, []string{target}, nil, nil, nil); len(got) != 0 {
			t.Errorf("unexpected Cognito match %q: %+v", target, got)
		}
	}
}

func TestBeanstalkOnlyMatchesRegionalAvailabilityNames(t *testing.T) {
	rule := auditedRule(t, "aws-elastic-beanstalk")
	if got := ruleengine.MatchDNS(rule, []string{"myapp.us-east-1.elasticbeanstalk.com"}, nil, nil, nil); len(got) != 1 {
		t.Fatalf("regional Beanstalk target missing: %+v", got)
	}
	for _, target := range []string{
		"myapp.elasticbeanstalk.com",
		"myapp.bx7dx222kw.us-east-2.elasticbeanstalk.com",
		"myapp.us-east-1.elasticbeanstalk.com.attacker.test",
	} {
		if got := ruleengine.MatchDNS(rule, []string{target}, nil, nil, nil); len(got) != 0 {
			t.Errorf("unsupported Beanstalk alias %q matched: %+v", target, got)
		}
	}
}

func TestAzureExcludesProtectedAndUnrelatedTargets(t *testing.T) {
	rule := auditedRule(t, "microsoft-azure")
	if rule.Status != "edge_case" {
		t.Fatal("Azure NXDOMAIN cannot certify claimability across resource types")
	}
	for _, target := range []string{"app.azurewebsites.net", "profile.trafficmanager.net", "frontdoor.azurefd.net"} {
		if got := ruleengine.MatchDNS(rule, []string{target}, nil, nil, nil); len(got) != 1 {
			t.Errorf("expected documented Azure resource target %q: %+v", target, got)
		}
	}
	for _, target := range []string{
		"app-a6gqaeashthkhkeu.eastus-01.azurewebsites.net",
		"my.visualstudio.com",
		"store.azuredatalakestore.net",
		"app.azurewebsites.net.attacker.test",
	} {
		if got := ruleengine.MatchDNS(rule, []string{target}, nil, nil, nil); len(got) != 0 {
			t.Errorf("protected or unrelated Azure target %q matched: %+v", target, got)
		}
	}
}

func TestDigitalOceanNameserversAndCurrentSurgeTargets(t *testing.T) {
	digitalOcean := auditedRule(t, "digital-ocean")
	for _, ns := range []string{"ns1.digitalocean.com", "ns2.digitalocean.com", "ns3.digitalocean.com"} {
		if got := ruleengine.MatchDNS(digitalOcean, nil, nil, nil, []string{ns}); len(got) != 1 {
			t.Errorf("expected official DigitalOcean nameserver %q: %+v", ns, got)
		}
	}
	if got := ruleengine.MatchDNS(digitalOcean, nil, nil, nil, []string{"other.digitalocean.com"}); len(got) != 0 {
		t.Errorf("unrelated DigitalOcean name matched: %+v", got)
	}
	surge := auditedRule(t, "surge-sh")
	for _, target := range []string{"geo.surge.world", "geo.surge.sh", "na-west1.surge.sh"} {
		if got := ruleengine.MatchDNS(surge, []string{target}, nil, nil, nil); len(got) != 1 {
			t.Errorf("current or legacy Surge target %q missing: %+v", target, got)
		}
	}
	if got := ruleengine.MatchDNS(surge, nil, []string{"138.197.235.123"}, nil, nil); len(got) != 1 {
		t.Errorf("documented Surge A record missing: %+v", got)
	}
}

func TestReadTheDocsOfficialCommunityApexTarget(t *testing.T) {
	rule := auditedRule(t, "readthedocs")
	if got := ruleengine.MatchDNS(rule, []string{"readthedocs.io"}, nil, nil, nil); len(got) != 1 {
		t.Fatalf("official Read the Docs Community target must match: %+v", got)
	}
	if got := ruleengine.MatchDNS(rule, []string{"project.readthedocs.io"}, nil, nil, nil); len(got) != 0 {
		t.Fatalf("project subdomain is not the documented custom-domain target: %+v", got)
	}
}
