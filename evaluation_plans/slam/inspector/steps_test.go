package inspector

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/reusable_steps"
	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
	sdkconfig "github.com/privateerproj/privateer-sdk/config"
)

const assessmentURL = "https://github.com/example/widget/blob/main/docs/security/self-assessment.md"

func ptrTo[T any](v T) *T { return &v }

func newPayload(self si.Assessment) data.Payload {
	payload := data.Payload{
		Owner:    "example",
		Repo:     "widget",
		Config:   &sdkconfig.Config{},
		Evidence: &gemara.EvidenceCollector{},
	}
	payload.Insights.Project = &si.Project{Name: "Widget"}
	payload.Insights.Repository = &si.Repository{Url: "https://github.com/example/widget"}
	payload.Insights.Repository.SecurityPosture.Assessments.Self = self
	return payload
}

func stubFetch(t *testing.T, fetched data.FetchedURL, err error) {
	t.Helper()
	original := fetchURL
	t.Cleanup(func() { fetchURL = original })
	fetchURL = func(_ *data.Payload, url string) (data.FetchedURL, error) {
		fetched.URL = url
		return fetched, err
	}
}

type fakeAIClient struct {
	body    string
	prompt  string
	content string
}

func (c *fakeAIClient) Analyze(_ context.Context, prompt, content string, _ *sdkai.Schema) (*sdkai.AnalyzeResponse, error) {
	c.prompt, c.content = prompt, content
	return &sdkai.AnalyzeResponse{
		JSON:     json.RawMessage(c.body),
		Metadata: sdkai.ResponseMetadata{Provider: sdkai.ProviderOpenAI, Model: "test-model", RequestID: "req-inspector"},
	}, nil
}

func stubAIClient(t *testing.T, client sdkai.Client) {
	t.Helper()
	original := reusable_steps.NewAIClient
	t.Cleanup(func() { reusable_steps.NewAIClient = original })
	reusable_steps.NewAIClient = func(sdkconfig.Config) (sdkai.Client, error) { return client, nil }
}

func TestSelfAssessmentDeclared(t *testing.T) {
	tests := []struct {
		name        string
		self        si.Assessment
		wantResult  gemara.Result
		wantMessage string
	}{
		{"evidence url", si.Assessment{Evidence: ptrTo(si.URL(assessmentURL))}, gemara.Passed, assessmentURL},
		{"comment only quotes the comment", si.Assessment{Comment: "A security self-assessment is in progress but not yet merged or published."}, gemara.Failed, "in progress but not yet merged"},
		{"name only", si.Assessment{Name: ptrTo("Self assessment")}, gemara.Failed, "does not declare"},
		{"blank url", si.Assessment{Evidence: ptrTo(si.URL("  "))}, gemara.Failed, "does not declare"},
		{"nothing", si.Assessment{}, gemara.Failed, "does not declare"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, message, _ := SelfAssessmentDeclared(newPayload(tt.self))
			if result != tt.wantResult || !strings.Contains(message, tt.wantMessage) {
				t.Errorf("got %v %q, want %v containing %q", result, message, tt.wantResult, tt.wantMessage)
			}
		})
	}
}

func TestSelfAssessmentResolves(t *testing.T) {
	tests := []struct {
		name       string
		fetched    data.FetchedURL
		err        error
		wantResult gemara.Result
	}{
		{"ok", data.FetchedURL{StatusCode: 200}, nil, gemara.Passed},
		{"not found", data.FetchedURL{StatusCode: 404}, nil, gemara.Failed},
		{"fetch error", data.FetchedURL{}, errors.New("refusing to fetch"), gemara.Failed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubFetch(t, tt.fetched, tt.err)
			result, message, _ := SelfAssessmentResolves(newPayload(si.Assessment{Evidence: ptrTo(si.URL(assessmentURL))}))
			if result != tt.wantResult {
				t.Errorf("got %v %q, want %v", result, message, tt.wantResult)
			}
		})
	}
}

func TestAIReviewSelfAssessment(t *testing.T) {
	const passBody = `{"result":"pass","confidence":"high","message":"Self-assessment covers all five topics","explanation":"Each topic is addressed for Widget.","citations":["` + assessmentURL + `"]}`
	tests := []struct {
		name         string
		fetched      data.FetchedURL
		wantContent  string
		wantComplete bool
	}{
		{"markdown", data.FetchedURL{StatusCode: 200, ContentType: "text/plain", Body: []byte("# Widget self-assessment")}, "# Widget self-assessment", true},
		{"html is reduced to text", data.FetchedURL{StatusCode: 200, ContentType: "text/html; charset=utf-8", Body: []byte("<html><head><title>x</title><script>nav()</script></head><body><h1>Widget &amp; threats</h1><p>Scope</p></body></html>")}, "Widget & threats\nScope", true},
		{"fetch truncation is noted", data.FetchedURL{StatusCode: 200, Body: []byte("partial"), Truncated: true}, "partial", false},
		{"oversized content is capped", data.FetchedURL{StatusCode: 200, Body: []byte(strings.Repeat("a", maxAssessmentContentBytes+10))}, strings.Repeat("a", maxAssessmentContentBytes), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubFetch(t, tt.fetched, nil)
			client := &fakeAIClient{body: passBody}
			stubAIClient(t, client)
			payload := newPayload(si.Assessment{Name: ptrTo("Widget self-assessment"), Comment: "Reviewed yearly", Date: "2026-09-01", Evidence: ptrTo(si.URL(assessmentURL))})

			result, _, confidence := AIReviewSelfAssessment(payload)

			if result != gemara.Passed || confidence != gemara.High {
				t.Fatalf("got %v %v, want Passed High", result, confidence)
			}
			var packet selfAssessmentAIEvidence
			if err := json.Unmarshal([]byte(client.content), &packet); err != nil {
				t.Fatal(err)
			}
			if packet.Document.Content != tt.wantContent {
				t.Errorf("content = %q, want %q", packet.Document.Content, tt.wantContent)
			}
			if packet.Collection.Complete != tt.wantComplete || (packet.Collection.Note != "") == tt.wantComplete {
				t.Errorf("collection = %+v, want complete %v with a note only when incomplete", packet.Collection, tt.wantComplete)
			}
			want := selfAssessmentAIEvidence{
				Project:        projectIdentity{Name: "Widget", RepositoryURL: "https://github.com/example/widget", ScannedRepository: "example/widget"},
				SelfAssessment: assessmentDeclaration{Name: "Widget self-assessment", Comment: "Reviewed yearly", Date: "2026-09-01", Evidence: assessmentURL},
			}
			if packet.Project != want.Project || packet.SelfAssessment != want.SelfAssessment || packet.Document.SourceURL != assessmentURL {
				t.Errorf("packet = %+v", packet)
			}
			evidence := payload.GetEvidence()
			if len(evidence) != 1 || !strings.Contains(evidence[0].Description, assessmentURL) {
				t.Errorf("evidence = %+v, want one AI record naming %s", evidence, assessmentURL)
			}
		})
	}
}

func TestAIReviewSelfAssessmentPrompt(t *testing.T) {
	stubFetch(t, data.FetchedURL{StatusCode: 200, Body: []byte("x")}, nil)
	client := &fakeAIClient{body: `{"result":"fail","confidence":"high","message":"m","explanation":"e"}`}
	stubAIClient(t, client)

	AIReviewSelfAssessment(newPayload(si.Assessment{Evidence: ptrTo(si.URL(assessmentURL))}))

	golden, err := os.ReadFile("testdata/self_assessment_coverage_prompt.golden")
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.TrimSuffix(string(golden), "\n"); client.prompt != want {
		t.Errorf("prompt drifted from golden file:\n%s", client.prompt)
	}
}

func TestAIReviewSelfAssessmentWithoutAI(t *testing.T) {
	stubFetch(t, data.FetchedURL{StatusCode: 200, Body: []byte("x")}, nil)
	stubAIClient(t, nil)
	result, _, _ := AIReviewSelfAssessment(newPayload(si.Assessment{Evidence: ptrTo(si.URL(assessmentURL))}))
	if result != gemara.NeedsReview {
		t.Errorf("got %v, want NeedsReview", result)
	}
}

func TestSameRepoLinks(t *testing.T) {
	const index = "https://github.com/example/widget/blob/main/docs/security/README.md"
	body := `[caps](capability-catalog.yaml) [threats](./threat-catalog.yaml#top) [again](threat-catalog.yaml)
[arch](../../ARCHITECTURE.md) [specs](../../openspec/specs/) [self](README.md) [anchor](#scope)
[ccc](https://github.com/finos/common-cloud-controls) [other repo](https://github.com/example/other/blob/main/x.md)
[tree](https://github.com/example/widget/tree/main/docs) [escape](../../../../other/blob/main/y.md)
<a href="https://github.com/example/widget/blob/main/SECURITY.md">policy</a>`
	want := []string{
		"https://github.com/example/widget/blob/main/docs/security/capability-catalog.yaml",
		"https://github.com/example/widget/blob/main/docs/security/threat-catalog.yaml",
		"https://github.com/example/widget/blob/main/ARCHITECTURE.md",
		"https://github.com/example/widget/blob/main/SECURITY.md",
	}
	if got := sameRepoLinks(index, body); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := sameRepoLinks("https://widget.example.com/security", body); got != nil {
		t.Errorf("non-GitHub evidence: got %v, want none", got)
	}
}

// An index page is sent with the catalogs it links to; a missing link marks
// the collection incomplete and is listed.
func TestAIReviewSelfAssessmentFollowsLinks(t *testing.T) {
	base := "https://github.com/example/widget/blob/main/docs/security/"
	pages := map[string]data.FetchedURL{
		base + "README.md":               {StatusCode: 200, Body: []byte("[caps](capability-catalog.yaml) [threats](threat-catalog.yaml) [gone](missing.md)")},
		base + "capability-catalog.yaml": {StatusCode: 200, Body: []byte("capabilities: [WIDGET.CAP01]")},
		base + "threat-catalog.yaml":     {StatusCode: 200, Body: []byte("threats: [WIDGET.THR01]")},
		base + "missing.md":              {StatusCode: 404},
	}
	original := fetchURL
	t.Cleanup(func() { fetchURL = original })
	fetchURL = func(_ *data.Payload, url string) (data.FetchedURL, error) { return pages[url], nil }
	client := &fakeAIClient{body: `{"result":"pass","confidence":"high","message":"m","explanation":"e"}`}
	stubAIClient(t, client)

	AIReviewSelfAssessment(newPayload(si.Assessment{Evidence: ptrTo(si.URL(base + "README.md"))}))

	var packet selfAssessmentAIEvidence
	if err := json.Unmarshal([]byte(client.content), &packet); err != nil {
		t.Fatal(err)
	}
	if len(packet.Linked) != 2 || packet.Linked[1].Content != "threats: [WIDGET.THR01]" {
		t.Errorf("linked = %+v, want both catalogs", packet.Linked)
	}
	if packet.Collection.Complete || len(packet.Collection.Unretrieved) != 1 || !strings.Contains(packet.Collection.Unretrieved[0], "missing.md: HTTP 404") {
		t.Errorf("collection = %+v, want incomplete with missing.md listed", packet.Collection)
	}
}
