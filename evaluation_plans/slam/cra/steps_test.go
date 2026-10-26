package cra

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/reusable_steps"
	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
	sdkconfig "github.com/privateerproj/privateer-sdk/config"
)

const (
	policyURL       = "https://github.com/example/.github/blob/main/SECURITY.md"
	outOfScopeURL   = "https://github.com/example/out/blob/main/SECURITY.md"
	contributingURL = "https://github.com/example/project/blob/main/CONTRIBUTING.md"
	passBody        = `{"result":"pass","confidence":"high","message":"Steward asks are met","explanation":"Reporting process and escalation section present.","citations":["SECURITY.md"]}`
)

// wrapped is the statement as a markdown file would line-wrap it.
var wrapped = "# Security\n\n" + strings.ReplaceAll(StewardStatement, " reported through", "\nreported through") + "\n\nReport privately via GitHub.\n"

func ptr[T any](v T) *T { return &v }

func craPayload() data.Payload {
	payload := data.Payload{Config: &sdkconfig.Config{}, Evidence: &gemara.EvidenceCollector{}}
	payload.Insights.Project = &si.Project{}
	payload.Insights.Project.VulnerabilityReporting = si.VulnerabilityReporting{
		ReportsAccepted: true,
		Policy:          ptr(si.URL(policyURL)),
		Contact:         &si.Contact{Name: "Security team", Email: ptr(si.Email("security@example.org"))},
		Comment:         ptr("Use GitHub private vulnerability reporting."),
	}
	payload.Insights.Repository = &si.Repository{Documentation: &si.RepositoryDocumentation{ContributingGuide: ptr(si.URL(contributingURL))}}
	return payload
}

// stubSources serves urls via FetchURL and files via GetFileContent; anything
// else is unavailable.
func stubSources(t *testing.T, urls, files map[string]string) {
	t.Helper()
	origFetch, origFile := fetchURL, getFileContent
	t.Cleanup(func() { fetchURL, getFileContent = origFetch, origFile })
	fetchURL = func(_ *data.Payload, u string) (data.FetchedURL, error) {
		body, ok := urls[u]
		if !ok {
			return data.FetchedURL{URL: u, StatusCode: 404}, nil
		}
		return data.FetchedURL{URL: u, StatusCode: 200, Body: []byte(body)}, nil
	}
	getFileContent = func(_ *data.Payload, path string) ([]byte, error) {
		body, ok := files[path]
		if !ok {
			return nil, errors.New("not found")
		}
		return []byte(body), nil
	}
}

func TestSecurityInsightsLinksPresent(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*data.Payload)
		result  gemara.Result
		message string
	}{
		{"complete", func(*data.Payload) {}, gemara.Passed, "contributing guide and accepts"},
		{"out of scope needs only the policy", func(p *data.Payload) {
			p.Insights.Project.VulnerabilityReporting.ReportsAccepted = false
			p.Insights.Repository.Documentation.ContributingGuide = nil
			p.Insights.Project.VulnerabilityReporting.Policy = ptr(si.URL(outOfScopeURL))
		}, gemara.Passed, "out of CRA scope"},
		{"in scope still needs everything", func(p *data.Payload) {
			p.Insights.Repository.Documentation.ContributingGuide = nil
		}, gemara.Failed, "contributing-guide is missing"},
		{"deprecated security-policy key", func(p *data.Payload) {
			p.Insights.Project.VulnerabilityReporting.Policy = nil
			p.Insights.Project.VulnerabilityReporting.SecurityPolicy = ptr(si.URL(policyURL))
		}, gemara.Passed, "Security Insights links"},
		{"repository security-policy", func(p *data.Payload) {
			p.Insights.Project.VulnerabilityReporting.Policy = nil
			p.Insights.Repository.Documentation.SecurityPolicy = ptr(si.URL(policyURL))
		}, gemara.Passed, "Security Insights links"},
		{"nothing declared", func(p *data.Payload) {
			p.Insights.Project.VulnerabilityReporting = si.VulnerabilityReporting{}
			p.Insights.Repository.Documentation.ContributingGuide = nil
		}, gemara.Failed, "project.vulnerability-reporting.policy (or repository.documentation.security-policy) is missing"},
	}
	stubSources(t, map[string]string{policyURL: wrapped, outOfScopeURL: OutOfScopeStatement}, nil)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := craPayload()
			test.mutate(&payload)
			result, message, _ := SecurityInsightsLinksPresent(payload)
			if result != test.result || !strings.Contains(message, test.message) {
				t.Errorf("got %v %q, want %v containing %q", result, message, test.result, test.message)
			}
		})
	}
}

func TestSecurityPolicyHasStewardStatement(t *testing.T) {
	tests := []struct {
		name     string
		unlinked bool
		urls     map[string]string
		files    map[string]string
		result   gemara.Result
		message  string
	}{
		{"declared link, line-wrapped", false, map[string]string{policyURL: wrapped}, nil, gemara.Passed, "appears verbatim in " + policyURL},
		{"no link: falls back to .github/SECURITY.md", true, nil, map[string]string{".github/SECURITY.md": wrapped}, gemara.Passed, "appears verbatim in .github/SECURITY.md"},
		{"declared link lacks it, repo file has it", false, map[string]string{policyURL: "# Security"}, map[string]string{"SECURITY.md": wrapped}, gemara.Failed, "appears verbatim in " + policyURL},
		{"declared link unresolvable, repo file has it", false, nil, map[string]string{"SECURITY.md": wrapped}, gemara.Failed, "linked from Security Insights could not be retrieved: " + policyURL},
		{"rendered HTML policy with auto-linked URL", false, map[string]string{policyURL: renderedPolicy(StewardStatement)}, nil, gemara.Passed, "LF CRA stewardship statement appears verbatim"},
		{"rendered HTML out-of-scope statement", false, map[string]string{policyURL: renderedPolicy(OutOfScopeStatement)}, nil, gemara.Passed, "out-of-scope statement appears verbatim"},
		{"markdown missing the out-of-scope link URL", false, map[string]string{policyURL: renderedOutOfScope}, nil, gemara.Failed, "Neither"},
		{"out-of-scope statement, line-wrapped", false, map[string]string{policyURL: strings.ReplaceAll(OutOfScopeStatement, " being used", "\nbeing used")}, nil, gemara.Passed, "out-of-scope statement appears verbatim in " + policyURL},
		{"both statements: LF wins", false, map[string]string{policyURL: OutOfScopeStatement + "\n\n" + wrapped}, nil, gemara.Passed, "LF CRA stewardship statement appears"},
		{"statement absent", false, map[string]string{policyURL: "# Security\nEmail us."}, map[string]string{"SECURITY.md": "# Security"}, gemara.Failed, "appears verbatim in " + policyURL},
		{"reworded statement", false, map[string]string{policyURL: strings.Replace(StewardStatement, "CRA stewardship:", "**CRA stewardship:**", 1)}, nil, gemara.Failed, "Neither"},
		{"no policy anywhere", true, nil, nil, gemara.Failed, "No security policy could be retrieved"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stubSources(t, test.urls, test.files)
			payload := craPayload()
			if test.unlinked {
				payload.Insights.Project.VulnerabilityReporting.Policy = nil
			}
			result, message, _ := SecurityPolicyHasStewardStatement(payload)
			if result != test.result || !strings.Contains(message, test.message) {
				t.Errorf("got %v %q, want %v containing %q", result, message, test.result, test.message)
			}
		})
	}
}

// renderedPolicy is statement as GitHub renders a SECURITY.md page: its URLs
// auto-linked and the markdown link turned into an anchor.
func renderedPolicy(statement string) string {
	body := regexp.MustCompile(`\[([^\]]*)\]\(([^)]*)\)`).ReplaceAllString(statement, `<a href="$2">$1</a>`)
	body = strings.Replace(body, "https://www.linuxfoundation.org/security", `<a href="https://www.linuxfoundation.org/security" rel="nofollow">https://www.linuxfoundation.org/security</a>`, 1)
	body = strings.ReplaceAll(body, "project's", "project&#39;s")
	return "<!DOCTYPE html><html><head><title>Security</title><script>x()</script></head><body><nav>Skip</nav><article><h1>Security</h1><p>" + body + "</p></article></body></html>"
}

type fakeAIClient struct {
	calls           int
	prompt, content string
}

func (c *fakeAIClient) Analyze(_ context.Context, prompt, content string, _ *sdkai.Schema) (*sdkai.AnalyzeResponse, error) {
	c.calls++
	c.prompt, c.content = prompt, content
	return &sdkai.AnalyzeResponse{
		JSON:     json.RawMessage(passBody),
		Metadata: sdkai.ResponseMetadata{Provider: sdkai.ProviderOpenAI, Model: "test-model", RequestID: "req-cra"},
	}, nil
}

func stubAI(t *testing.T, client sdkai.Client) {
	t.Helper()
	orig := reusable_steps.NewAIClient
	t.Cleanup(func() { reusable_steps.NewAIClient = orig })
	reusable_steps.NewAIClient = func(sdkconfig.Config) (sdkai.Client, error) { return client, nil }
}

func TestAIReviewReadinessPrompt(t *testing.T) {
	stubSources(t, map[string]string{policyURL: wrapped, contributingURL: "## Escalation"}, nil)
	client := &fakeAIClient{}
	stubAI(t, client)
	payload := craPayload()

	result, message, confidence := AIReviewReadiness(payload)

	if result != gemara.Passed || confidence != gemara.High || message != "[AI-Assisted] Reporting process and escalation section present." {
		t.Fatalf("got %v %v %q", result, confidence, message)
	}
	golden, err := os.ReadFile("testdata/cra_readiness_quality_prompt.golden")
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimSuffix(string(golden), "\n"); client.prompt != want {
		t.Errorf("prompt drifted from golden:\n%s", client.prompt)
	}
	var packet material
	if err := json.Unmarshal([]byte(client.content), &packet); err != nil {
		t.Fatal(err)
	}
	if !packet.Collection.Complete || packet.Scope != inScope || packet.SecurityPolicy.Source != policyURL ||
		packet.ContributingGuide == nil || packet.ContributingGuide.Source != contributingURL ||
		packet.SecurityInsights.ContactEmail != "security@example.org" {
		t.Errorf("unexpected material: %s", client.content)
	}
	evidence := payload.GetEvidence()
	if len(evidence) != 1 || !strings.Contains(evidence[0].Description, policyURL) || !strings.Contains(evidence[0].Description, contributingURL) {
		t.Errorf("unexpected evidence: %+v", evidence)
	}
}

func TestAIReviewReadinessCollection(t *testing.T) {
	stubSources(t, map[string]string{policyURL: wrapped + strings.Repeat("x", maxDocumentBytes)}, nil)
	client := &fakeAIClient{}
	stubAI(t, client)

	AIReviewReadiness(craPayload())

	var packet material
	if err := json.Unmarshal([]byte(client.content), &packet); err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(packet.Collection.Notes, "; ")
	if packet.Collection.Complete || !packet.SecurityPolicy.Truncated || len(packet.SecurityPolicy.Content) != maxDocumentBytes ||
		!strings.Contains(notes, "contributing_guide could not be retrieved") || !strings.Contains(notes, "security_policy truncated") {
		t.Errorf("unexpected collection: %+v", packet.Collection)
	}
}

func TestAIReviewReadinessOutOfScope(t *testing.T) {
	stubSources(t, map[string]string{policyURL: OutOfScopeStatement}, nil)
	orig := fetchURL
	fetchURL = func(p *data.Payload, u string) (data.FetchedURL, error) {
		if u == contributingURL {
			t.Errorf("contributing guide fetched for an out-of-scope project")
		}
		return orig(p, u)
	}
	client := &fakeAIClient{}
	stubAI(t, client)

	AIReviewReadiness(craPayload())

	var packet material
	if err := json.Unmarshal([]byte(client.content), &packet); err != nil {
		t.Fatal(err)
	}
	if packet.Scope != outOfScope || packet.ContributingGuide != nil || !packet.Collection.Complete {
		t.Errorf("unexpected material: %s", client.content)
	}
}

func TestAIReviewReadinessNotConfigured(t *testing.T) {
	stubSources(t, map[string]string{policyURL: wrapped}, nil)
	stubAI(t, nil)
	if result, _, _ := AIReviewReadiness(craPayload()); result != gemara.NeedsReview {
		t.Errorf("got %v, want NeedsReview", result)
	}
}

func TestFailuresLinkTheSecurityPolicy(t *testing.T) {
	stubSources(t, map[string]string{policyURL: "# Security\nEmail us."}, nil)
	_, message, _ := SecurityPolicyHasStewardStatement(craPayload())
	if !strings.HasSuffix(message, "Security policy for review: "+policyURL) {
		t.Errorf("declared policy: message %q does not end with its link", message)
	}

	stubSources(t, nil, map[string]string{".github/SECURITY.md": "# Security"})
	payload := craPayload()
	payload.Owner, payload.Repo, payload.DefaultBranch = "example", "project", "main"
	payload.Insights.Project.VulnerabilityReporting = si.VulnerabilityReporting{}
	_, message, _ = SecurityInsightsLinksPresent(payload)
	if !strings.HasSuffix(message, "Security policy for review: https://github.com/example/project/blob/main/.github/SECURITY.md") {
		t.Errorf("undeclared policy: message %q does not link the repository's SECURITY.md", message)
	}
}

func TestOtherStewardIsMarkedForReview(t *testing.T) {
	stubSources(t, map[string]string{policyURL: "# Security"}, nil)
	client := &fakeAIClient{}
	stubAI(t, client)
	for uri, wantReview := range map[string]bool{"https://www.apache.org": true, "https://www.cncf.io/projects/": false, "https://lfx.linuxfoundation.org/x": false} {
		payload := craPayload()
		payload.Insights.Project.Steward = &si.Link{Uri: uri}
		for name, step := range map[string]func(data.Payload) (gemara.Result, string, gemara.ConfidenceLevel){
			"SecurityInsightsLinksPresent": SecurityInsightsLinksPresent, "SecurityPolicyHasStewardStatement": SecurityPolicyHasStewardStatement,
			"ReportingChannelsWork": ReportingChannelsWork, "AIReviewReadiness": AIReviewReadiness,
		} {
			result, message, _ := step(payload)
			if got := result == gemara.NeedsReview && strings.Contains(message, "Security policy for review: "+policyURL); got != wantReview {
				t.Errorf("%s with steward %s: got %v %q, want marked for review %v", name, uri, result, message, wantReview)
			}
		}
	}
	if client.calls != 2 {
		t.Errorf("AI calls = %d, want 2: the two LF stewards only", client.calls)
	}
}

func TestReportingChannelsWork(t *testing.T) {
	escalation := "## Escalation\nWe escalate to steward@linuxfoundation.org.\n"
	pvrPolicy := wrapped + "Use https://github.com/example/project/security/advisories/new\n"
	tests := []struct {
		name    string
		urls    map[string]string
		enabled bool
		err     error
		want    gemara.Result
		wantMsg string
	}{
		{"all present", map[string]string{policyURL: pvrPolicy, contributingURL: escalation}, true, nil, gemara.Passed, "names steward@linuxfoundation.org"},
		{"private reporting off", map[string]string{policyURL: pvrPolicy, contributingURL: escalation}, false, nil, gemara.Failed, "not enabled on example/project"},
		{"private reporting unreadable", map[string]string{policyURL: pvrPolicy, contributingURL: escalation}, false, errors.New("403"), gemara.NeedsReview, "403"},
		{"no steward address", map[string]string{policyURL: wrapped, contributingURL: "# Contributing"}, true, nil, gemara.Failed, "does not name the steward escalation address"},
		{"out of scope owes nothing", map[string]string{policyURL: OutOfScopeStatement}, false, nil, gemara.Passed, "out of CRA scope"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubSources(t, tt.urls, nil)
			orig := privateReportingEnabled
			privateReportingEnabled = func(_ *data.Payload, owner, repo string) (bool, error) {
				if owner != "example" || repo != "project" {
					t.Errorf("checked %s/%s", owner, repo)
				}
				return tt.enabled, tt.err
			}
			t.Cleanup(func() { privateReportingEnabled = orig })
			payload := craPayload()
			payload.Insights.Project.VulnerabilityReporting.Comment = nil
			result, message, _ := ReportingChannelsWork(payload)
			if result != tt.want || !strings.Contains(message, tt.wantMsg) {
				t.Errorf("got %v %q, want %v containing %q", result, message, tt.want, tt.wantMsg)
			}
		})
	}
}
