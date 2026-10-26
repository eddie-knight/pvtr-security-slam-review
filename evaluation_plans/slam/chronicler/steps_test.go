package chronicler

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

const (
	guideURL        = "https://example.org/docs/quickstart"
	contributingURL = "https://github.com/example/widget/blob/main/README.md#contributing"
	securityURL     = "https://github.com/example/widget/blob/main/SECURITY.md"
	changelogURL    = "https://github.com/example/widget/releases/tag/{version}"
)

func ptrTo[T any](v T) *T { return &v }

// newPayload declares the Level 1 documentation, with the security policy
// linked from both fields that may hold it.
func newPayload() data.Payload {
	payload := data.Payload{Config: &sdkconfig.Config{}, Evidence: &gemara.EvidenceCollector{}}
	payload.Insights.Project = &si.Project{Documentation: &si.ProjectDocumentation{QuickstartGuide: ptrTo(si.URL(guideURL))}}
	payload.Insights.Project.VulnerabilityReporting.Policy = ptrTo(si.URL(securityURL))
	payload.Insights.Repository = &si.Repository{
		Documentation: &si.RepositoryDocumentation{
			ContributingGuide: ptrTo(si.URL(contributingURL)),
			SecurityPolicy:    ptrTo(si.URL(securityURL)),
		},
		ReleaseDetails: &si.ReleaseDetails{},
	}
	return payload
}

func stubFetch(t *testing.T, fetch func(url string) (data.FetchedURL, error)) *[]string {
	t.Helper()
	var calls []string
	original := fetchURL
	t.Cleanup(func() { fetchURL = original })
	fetchURL = func(_ *data.Payload, url string) (data.FetchedURL, error) {
		calls = append(calls, url)
		return fetch(url)
	}
	return &calls
}

func okFetch(url string) (data.FetchedURL, error) {
	return data.FetchedURL{URL: url, StatusCode: 200, ContentType: "text/plain", Body: []byte("doc at " + url)}, nil
}

func TestDocumentationLinksPresent(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*data.Payload)
		result  gemara.Result
		message string
	}{
		{"level 1 declared", func(*data.Payload) {}, gemara.Passed, "not declared: project.documentation.detailed-guide"},
		{"detailed guide is a user guide", func(p *data.Payload) {
			p.Insights.Project.Documentation.QuickstartGuide = nil
			p.Insights.Project.Documentation.DetailedGuide = ptrTo(si.URL(guideURL))
		}, gemara.Passed, "declared: project.documentation.detailed-guide"},
		{"either security policy field", func(p *data.Payload) {
			p.Insights.Repository.Documentation.SecurityPolicy = nil
		}, gemara.Passed, "declared: project.documentation.quickstart-guide"},
		{"no user guide", func(p *data.Payload) {
			p.Insights.Project.Documentation.QuickstartGuide = nil
		}, gemara.Failed, "Maturity Level 1 documentation: user guide"},
		{"nothing declared", func(p *data.Payload) {
			p.Insights.Project.Documentation.QuickstartGuide = nil
			p.Insights.Project.VulnerabilityReporting.Policy = nil
			p.Insights.Repository.Documentation = &si.RepositoryDocumentation{}
		}, gemara.Failed, "user guide (project.documentation.quickstart-guide or detailed-guide); contributing guide (repository.documentation.contributing-guide); security policy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := newPayload()
			tt.mutate(&payload)
			result, message, _ := DocumentationLinksPresent(payload)
			if result != tt.result || !strings.Contains(message, tt.message) {
				t.Fatalf("got %v %q, want %v containing %q", result, message, tt.result, tt.message)
			}
			if strings.Contains(message, deprecatedSecurityPolicy) {
				t.Errorf("message reports the deprecated alias: %q", message)
			}
		})
	}
}

func TestDocumentationLinksResolve(t *testing.T) {
	tests := []struct {
		name    string
		fetch   func(string) (data.FetchedURL, error)
		result  gemara.Result
		message string
	}{
		{"all resolve", okFetch, gemara.Passed, "All 4 documentation links"},
		{"404", func(url string) (data.FetchedURL, error) {
			if url == guideURL {
				return data.FetchedURL{URL: url, StatusCode: 404}, nil
			}
			return okFetch(url)
		}, gemara.Failed, "project.documentation.quickstart-guide (" + guideURL + "): HTTP 404"},
		{"fetch error", func(url string) (data.FetchedURL, error) {
			return data.FetchedURL{URL: url}, errors.New("dial failed")
		}, gemara.Failed, "repository.documentation.security-policy (" + securityURL + "): dial failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubFetch(t, tt.fetch)
			payload := newPayload()
			payload.Insights.Repository.ReleaseDetails.Changelog = ptrTo(si.URL(changelogURL))
			result, message, _ := DocumentationLinksResolve(payload)
			if result != tt.result || !strings.Contains(message, tt.message) {
				t.Fatalf("got %v %q, want %v containing %q", result, message, tt.result, tt.message)
			}
			if result == gemara.Passed && !strings.Contains(message, "placeholder: repository.release.changelog") {
				t.Errorf("templated changelog not reported as skipped: %q", message)
			}
		})
	}
}

type fakeAIClient struct {
	body, prompt, content string
}

func (c *fakeAIClient) Analyze(_ context.Context, prompt, content string, _ *sdkai.Schema) (*sdkai.AnalyzeResponse, error) {
	c.prompt, c.content = prompt, content
	return &sdkai.AnalyzeResponse{
		JSON:     json.RawMessage(c.body),
		Metadata: sdkai.ResponseMetadata{Provider: sdkai.ProviderOpenAI, Model: "test-model", RequestID: "req-chronicler"},
	}, nil
}

func stubAIClient(t *testing.T, client sdkai.Client) {
	t.Helper()
	original := reusable_steps.NewAIClient
	t.Cleanup(func() { reusable_steps.NewAIClient = original })
	reusable_steps.NewAIClient = func(sdkconfig.Config) (sdkai.Client, error) { return client, nil }
}

func TestAIReviewDocumentation(t *testing.T) {
	stubFetch(t, func(url string) (data.FetchedURL, error) {
		if url == guideURL {
			return data.FetchedURL{URL: url, StatusCode: 200, ContentType: "text/html; charset=utf-8",
				Body: []byte(`<html><head><title>x</title></head><body><script>evil()</script><h1>Quick &amp; easy</h1><p>Install it.</p></body></html>`)}, nil
		}
		return okFetch(url)
	})
	client := &fakeAIClient{body: `{"result":"pass","confidence":"high","message":"Every declared document covers its topic","explanation":"All documents are real."}`}
	stubAIClient(t, client)
	payload := newPayload()
	payload.Insights.Repository.ReleaseDetails.Changelog = ptrTo(si.URL(changelogURL))

	result, message, confidence := AIReviewDocumentation(payload)

	if result != gemara.Passed || confidence != gemara.High || message != "[AI-Assisted] All documents are real. [AI input was incomplete: https://github.com/example/widget/releases/tag/{version}: URL contains a placeholder]" {
		t.Fatalf("got %v %v %q", result, confidence, message)
	}
	golden, err := os.ReadFile("testdata/chronicler_documentation_quality_prompt.golden")
	if err != nil {
		t.Fatal(err)
	}
	if client.prompt != strings.TrimSuffix(string(golden), "\n") {
		t.Errorf("prompt differs from golden:\n%s", client.prompt)
	}

	var packet documentationMaterial
	if err := json.Unmarshal([]byte(client.content), &packet); err != nil {
		t.Fatal(err)
	}
	if len(packet.Documents) != 4 {
		t.Fatalf("want 4 documents (security policy deduplicated), got %d", len(packet.Documents))
	}
	guide, contributing, security, changelog := packet.Documents[0], packet.Documents[1], packet.Documents[2], packet.Documents[3]
	if guide.Content != "Quick & easy\nInstall it." {
		t.Errorf("HTML not reduced to text: %q", guide.Content)
	}
	if contributing.Section != "contributing" || contributing.SourceURL != contributingURL {
		t.Errorf("anchor not kept: %+v", contributing)
	}
	if len(security.DeclaredFor) != 2 || security.DeclaredFor[1].Field != "repository.documentation.security-policy" {
		t.Errorf("security policy declarations not merged: %+v", security.DeclaredFor)
	}
	if changelog.Content != "" || len(packet.Collection.NotRetrieved) != 1 || !strings.Contains(packet.Collection.NotRetrieved[0], "placeholder") {
		t.Errorf("templated changelog not reported as not retrieved: %+v %v", changelog, packet.Collection.NotRetrieved)
	}
	if evidence := payload.GetEvidence(); len(evidence) != 1 || !strings.Contains(evidence[0].Description, securityURL) {
		t.Errorf("AI evidence not recorded with sources: %+v", evidence)
	}
}

func TestAIReviewDocumentationNotConfigured(t *testing.T) {
	stubFetch(t, okFetch)
	stubAIClient(t, nil)
	if result, _, _ := AIReviewDocumentation(newPayload()); result != gemara.NeedsReview {
		t.Fatalf("got %v, want NeedsReview", result)
	}
}

func TestDocumentationEvidenceCaps(t *testing.T) {
	big := strings.Repeat("é", maxDocumentChars) // two bytes each: cut mid-rune
	stubFetch(t, func(url string) (data.FetchedURL, error) {
		return data.FetchedURL{URL: url, StatusCode: 200, Body: []byte(big)}, nil
	})
	payload := newPayload()
	docs := payload.Insights.Project.Documentation
	for i, u := range []**si.URL{&docs.DetailedGuide, &docs.Design, &docs.CodeOfConduct, &docs.ReleaseProcess, &docs.SupportPolicy, &docs.SignatureVerification} {
		*u = ptrTo(si.URL("https://example.org/doc" + string(rune('a'+i))))
	}
	payload.Insights.Repository.Documentation.Governance = ptrTo(si.URL("https://example.org/gov"))
	payload.Insights.Repository.Documentation.ReviewPolicy = ptrTo(si.URL("https://example.org/review"))

	material, _, _ := documentationEvidence(payload)

	var packet documentationMaterial
	if err := json.Unmarshal([]byte(material), &packet); err != nil {
		t.Fatal(err)
	}
	total, excluded := 0, 0
	for _, doc := range packet.Documents {
		total += len(doc.Content)
		if doc.Content != "" && (!doc.Truncated || len(doc.Content) > maxDocumentChars || strings.ContainsRune(doc.Content, '�')) {
			t.Errorf("%s not capped cleanly: %d bytes, truncated=%v", doc.SourceURL, len(doc.Content), doc.Truncated)
		}
		if doc.NotIncluded != "" {
			excluded++
		}
	}
	if total > maxMaterialChars || excluded == 0 {
		t.Errorf("total cap not applied: %d bytes, %d excluded", total, excluded)
	}
}

// A page past the old 16K cap, with its topic at the end (Meshery's release
// support section), reaches the model whole.
func TestLongDocumentSentWhole(t *testing.T) {
	body := "# Build and release\n" + strings.Repeat("filler\n", 40*1024/7) + "## Release support\nThe last two minor releases are supported.\n"
	stubFetch(t, func(url string) (data.FetchedURL, error) {
		return data.FetchedURL{URL: url, StatusCode: 200, Body: []byte(body)}, nil
	})

	material, _, incomplete := documentationEvidence(newPayload())

	var packet documentationMaterial
	if err := json.Unmarshal([]byte(material), &packet); err != nil {
		t.Fatal(err)
	}
	guide := packet.Documents[0]
	if len(body) <= 16*1024 || guide.Content != body || guide.Truncated || len(incomplete) != 0 {
		t.Errorf("got %d of %d chars, truncated=%v, incomplete=%v", len(guide.Content), len(body), guide.Truncated, incomplete)
	}
}

func TestLongDocumentStartsAtSection(t *testing.T) {
	body := "# Guide\n" + strings.Repeat("filler\n", maxDocumentChars) + "## Contributing!\nOpen a pull request.\n"
	stubFetch(t, func(url string) (data.FetchedURL, error) {
		return data.FetchedURL{URL: url, StatusCode: 200, Body: []byte(body)}, nil
	})

	material, _, _ := documentationEvidence(newPayload())

	var packet documentationMaterial
	if err := json.Unmarshal([]byte(material), &packet); err != nil {
		t.Fatal(err)
	}
	contributing, guide := packet.Documents[1], packet.Documents[0]
	if !contributing.FromSection || !strings.HasPrefix(contributing.Content, "## Contributing!\nOpen a pull request.") {
		t.Errorf("section window not applied: %+v", contributing.Content[:min(40, len(contributing.Content))])
	}
	if guide.FromSection || !strings.HasPrefix(guide.Content, "# Guide") {
		t.Errorf("document without a section was windowed")
	}
}

// Meshery's SECURITY.md only points to its docs site, which names the private
// reporting channel; a long document's links are not followed.
func TestShortDocumentLinksFollowed(t *testing.T) {
	const docsPage = "https://docs.example.org/security"
	stubFetch(t, func(url string) (data.FetchedURL, error) {
		switch url {
		case securityURL:
			return data.FetchedURL{URL: url, StatusCode: 200, Body: []byte("[![badge](https://img.example/b.svg)](https://ci.example/run)\nTo report a vulnerability see [security](" + docsPage + ") and [policy](SECURITY.md#top). Also <" + guideURL + ">.")}, nil
		case docsPage:
			return data.FetchedURL{URL: url, StatusCode: 200, ContentType: "text/html", Body: []byte("<p>Email the private security@example.org list.</p>")}, nil
		case guideURL:
			return data.FetchedURL{URL: url, StatusCode: 200, Body: []byte(strings.Repeat("x", maxDelegatingChars) + "[ignored](https://ignored.example/)")}, nil
		}
		return okFetch(url)
	})

	material, _, _ := documentationEvidence(newPayload())

	var packet documentationMaterial
	if err := json.Unmarshal([]byte(material), &packet); err != nil {
		t.Fatal(err)
	}
	var linked []string
	for _, doc := range packet.Documents {
		if doc.LinkedFrom != "" {
			linked = append(linked, doc.SourceURL+" <- "+doc.LinkedFrom+": "+doc.Content)
		}
	}
	want := []string{docsPage + " <- " + securityURL + ": Email the private security@example.org list."}
	if strings.Join(linked, "\n") != strings.Join(want, "\n") {
		t.Errorf("linked documents:\n%s\nwant:\n%s", strings.Join(linked, "\n"), strings.Join(want, "\n"))
	}
}
