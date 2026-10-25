package defender

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/reusable_steps"
	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
	sdkconfig "github.com/privateerproj/privateer-sdk/config"
)

const strimziPage = "https://grc.store/targets/strimzi/strimzi-kafka-operator"

// hub is a stubbed grc.store. The Strimzi fixtures are real responses from
// 2026-10-25: one target version, a recurring signed scan, one failed control.
type hub struct {
	target      *data.GrcStoreTarget
	targetErr   error
	evaluations []data.GrcStoreEvaluation
	evalErr     error
	log         []byte
	logErr      error
}

func readFixture(t *testing.T, name string, v any) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	if v != nil {
		if err := json.Unmarshal(raw, v); err != nil {
			t.Fatal(err)
		}
	}
	return raw
}

func strimziHub(t *testing.T) *hub {
	t.Helper()
	h := &hub{target: &data.GrcStoreTarget{}}
	readFixture(t, "strimzi_target.json", h.target)
	var page struct {
		Items []data.GrcStoreEvaluation `json:"items"`
	}
	readFixture(t, "strimzi_evaluations.json", &page)
	h.evaluations = page.Items
	h.log = readFixture(t, "strimzi_log.json", nil)
	return h
}

func (h *hub) install(t *testing.T) {
	t.Helper()
	target, evaluations, log, clock := getGrcStoreTarget, getGrcStoreEvaluations, getGrcStoreLog, now
	t.Cleanup(func() {
		getGrcStoreTarget, getGrcStoreEvaluations, getGrcStoreLog, now = target, evaluations, log, clock
	})
	getGrcStoreTarget = func(_ *data.Payload, namespace, id string) (*data.GrcStoreTarget, error) {
		return h.target, h.targetErr
	}
	getGrcStoreEvaluations = func(_ *data.Payload, namespace, id string, limit int) ([]data.GrcStoreEvaluation, error) {
		return h.evaluations, h.evalErr
	}
	getGrcStoreLog = func(_ *data.Payload, namespace, id, version string) ([]byte, error) {
		return h.log, h.logErr
	}
	now = func() time.Time { return time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC) }
}

func stubFetch(t *testing.T, fetch func(string) (data.FetchedURL, error)) {
	t.Helper()
	original := fetchURL
	t.Cleanup(func() { fetchURL = original })
	fetchURL = func(_ *data.Payload, rawURL string) (data.FetchedURL, error) { return fetch(rawURL) }
}

func strimziPayload(t *testing.T) data.Payload {
	t.Helper()
	raw, err := os.ReadFile("testdata/strimzi_security_insights.yml")
	if err != nil {
		t.Fatal(err)
	}
	insights, err := si.Load(raw)
	if err != nil {
		t.Fatal(err)
	}
	return data.Payload{
		Owner: "strimzi", Repo: "strimzi-kafka-operator",
		InsightsPath: "security-insights.yml", Insights: *insights,
		Evidence: &gemara.EvidenceCollector{},
	}
}

func payloadWithLocation(location string) data.Payload {
	return data.Payload{Insights: si.SecurityInsights{Repository: &si.Repository{
		SecurityPosture: si.SecurityPosture{Tools: []si.SecurityTool{{
			Name: "OSPS Baseline Scanner",
			Results: si.SecurityToolResults{Release: &si.Attestation{
				Location: si.URL(location),
			}},
		}}},
	}}}
}

type step func(data.Payload) (gemara.Result, string, gemara.ConfidenceLevel)

// Strimzi is the reference project: it earns SLAM-DE-01.01 and, with one
// failed control, does not yet earn SLAM-DE-01.02.
func Test_Strimzi(t *testing.T) {
	strimziHub(t).install(t)
	payload := strimziPayload(t)
	for name, s := range map[string]step{
		"GrcStoreTargetDeclared": GrcStoreTargetDeclared,
		"ResultPublished":        ResultPublished,
		"ResultIsRecurring":      ResultIsRecurring,
		"TrustedPublisher":       TrustedPublisher,
	} {
		if result, message, _ := s(payload); result != gemara.Passed {
			t.Errorf("%s = %v (%s), want Passed", name, result, message)
		}
	}
	result, message, _ := LatestResultHasNoFailures(payload)
	want := "The latest OSPS Baseline result for strimzi/strimzi-kafka-operator (1.3.0-20261025T171208Z) reports 1 failed control(s): OSPS-QA-03.01"
	if result != gemara.Failed || message != want {
		t.Errorf("LatestResultHasNoFailures = %v %q, want Failed %q", result, message, want)
	}
}

func Test_GrcStoreTargetDeclared(t *testing.T) {
	tests := []struct {
		name     string
		location string
		want     gemara.Result
	}{
		{"target page", strimziPage, gemara.Passed},
		{"trailing slash", strimziPage + "/", gemara.Passed},
		{"workflow page", "https://github.com/strimzi/strimzi-kafka-operator/actions/workflows/baseline.yml", gemara.Failed},
		{"namespace page", "https://grc.store/strimzi", gemara.Failed},
		{"http", "http://grc.store/targets/strimzi/strimzi-kafka-operator", gemara.Failed},
		{"lookalike host", "https://grc.store.example.com/targets/a/b", gemara.Failed},
		{"empty", "", gemara.Failed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if result, message, _ := GrcStoreTargetDeclared(payloadWithLocation(tt.location)); result != tt.want {
				t.Errorf("got %v (%s), want %v", result, message, tt.want)
			}
		})
	}
	if result, _, _ := GrcStoreTargetDeclared(data.Payload{Insights: si.SecurityInsights{Repository: &si.Repository{}}}); result != gemara.Failed {
		t.Errorf("no tools: got %v, want Failed", result)
	}
}

func Test_ResultPublished(t *testing.T) {
	notBaseline := strimziHub(t).target
	notBaseline.Versions[0].Latest.CatalogID = "some-other-catalog"
	tests := []struct {
		name string
		hub  hub
		want gemara.Result
	}{
		{"no target", hub{}, gemara.Failed},
		{"hub error", hub{targetErr: errors.New("boom")}, gemara.NeedsReview},
		{"no versions", hub{target: &data.GrcStoreTarget{}}, gemara.Failed},
		{"not a baseline catalog", hub{target: notBaseline}, gemara.Failed},
		{"strimzi", *strimziHub(t), gemara.Passed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.hub.install(t)
			if result, message, _ := ResultPublished(payloadWithLocation(strimziPage)); result != tt.want {
				t.Errorf("got %v (%s), want %v", result, message, tt.want)
			}
		})
	}
}

func Test_ResultIsRecurring(t *testing.T) {
	strimzi := strimziHub(t).evaluations
	sameTime := []data.GrcStoreEvaluation{strimzi[0], strimzi[0]}
	stale := []data.GrcStoreEvaluation{strimzi[0], strimzi[1]}
	stale[0].RunAt, stale[1].RunAt = "2026-08-02T00:00:00Z", "2026-08-01T00:00:00Z"
	tests := []struct {
		name string
		hub  hub
		want gemara.Result
	}{
		{"strimzi", hub{evaluations: strimzi}, gemara.Passed},
		{"single run", hub{evaluations: strimzi[:1]}, gemara.Failed},
		{"same run twice", hub{evaluations: sameTime}, gemara.Failed},
		{"stale", hub{evaluations: stale}, gemara.Failed},
		{"none", hub{}, gemara.Failed},
		{"hub error", hub{evalErr: errors.New("boom")}, gemara.NeedsReview},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.hub.install(t)
			if result, message, _ := ResultIsRecurring(payloadWithLocation(strimziPage)); result != tt.want {
				t.Errorf("got %v (%s), want %v", result, message, tt.want)
			}
		})
	}
}

func Test_TrustedPublisher(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*data.GrcStoreTarget)
		want    gemara.Result
		wantMsg string
	}{
		{"strimzi", func(*data.GrcStoreTarget) {}, gemara.Passed, "verified by GitHub OIDC"},
		{"unverified", func(t *data.GrcStoreTarget) { t.VerifiedAt = "" }, gemara.Failed, "not verified by GitHub OIDC"},
		{"other method", func(t *data.GrcStoreTarget) { t.VerificationMethod = "manual" }, gemara.Failed, "not verified by GitHub OIDC"},
		{"other repository", func(t *data.GrcStoreTarget) { t.URI = "https://github.com/someone/else" }, gemara.Failed, "is bound to https://github.com/someone/else"},
		{"uri case differs", func(t *data.GrcStoreTarget) { t.URI = "https://github.com/Strimzi/Strimzi-Kafka-Operator" }, gemara.Passed, "verified by GitHub OIDC"},
		{"published from a fork", func(t *data.GrcStoreTarget) {
			t.Versions[0].Latest.Signer.CallerRepository = "fork/strimzi-kafka-operator"
		}, gemara.Failed, `published from "fork/strimzi-kafka-operator"`},
		{"other workflow", func(t *data.GrcStoreTarget) {
			t.Versions[0].Latest.Signer.WorkflowRef = "strimzi/strimzi-kafka-operator/.github/workflows/publish.yml@refs/heads/main"
		}, gemara.Failed, "not the revanite-io/pvtr-publish-results publish workflow"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := strimziHub(t)
			tt.mutate(h.target)
			h.install(t)
			result, message, _ := TrustedPublisher(strimziPayload(t))
			if result != tt.want || !strings.Contains(message, tt.wantMsg) {
				t.Errorf("got %v %q, want %v containing %q", result, message, tt.want, tt.wantMsg)
			}
		})
	}
}

func Test_LatestResultHasNoFailures(t *testing.T) {
	h := strimziHub(t)
	h.target.Versions[0].Latest.Counts.Failed = 0
	h.install(t)
	if result, message, _ := LatestResultHasNoFailures(strimziPayload(t)); result != gemara.Passed {
		t.Errorf("no failures: got %v (%s), want Passed", result, message)
	}

	// The count decides; an unreadable log only loses the control names.
	h = strimziHub(t)
	h.logErr = errors.New("boom")
	h.install(t)
	result, message, _ := LatestResultHasNoFailures(strimziPayload(t))
	if result != gemara.Failed || !strings.HasSuffix(message, "reports 1 failed control(s)") {
		t.Errorf("log unavailable: got %v %q, want Failed without control names", result, message)
	}
}

type fakeAIClient struct {
	calls   int
	prompt  string
	content string
}

func (c *fakeAIClient) Analyze(_ context.Context, prompt, content string, _ *sdkai.Schema) (*sdkai.AnalyzeResponse, error) {
	c.calls++
	c.prompt, c.content = prompt, content
	return &sdkai.AnalyzeResponse{
		JSON:     json.RawMessage(`{"result":"fail","confidence":"high","message":"OSPS-SA-03.01 has no followable evidence","explanation":"The self assessment is still in progress."}`),
		Metadata: sdkai.ResponseMetadata{Provider: sdkai.ProviderOpenAI, Model: "test-model", RequestID: "req-defender"},
	}, nil
}

func stubAIClient(t *testing.T, client sdkai.Client) {
	t.Helper()
	original := reusable_steps.NewAIClient
	t.Cleanup(func() { reusable_steps.NewAIClient = original })
	reusable_steps.NewAIClient = func(sdkconfig.Config) (sdkai.Client, error) { return client, nil }
}

func Test_AIReviewUncheckedControlEvidence(t *testing.T) {
	strimziHub(t).install(t)
	var fetched []string
	stubFetch(t, func(rawURL string) (data.FetchedURL, error) {
		fetched = append(fetched, rawURL)
		if rawURL == "https://strimzi.io/documentation/" {
			return data.FetchedURL{StatusCode: 404}, nil
		}
		if strings.HasPrefix(rawURL, "https://strimzi.io/") {
			return data.FetchedURL{StatusCode: 200, ContentType: "text/html; charset=utf-8",
				Body: []byte("<html><head><style>p{}</style></head><body><h1>Docs</h1>\n\n<p>Kafka &amp; Kubernetes</p></body></html>")}, nil
		}
		return data.FetchedURL{StatusCode: 200, ContentType: "text/plain", Body: []byte("text of " + rawURL)}, nil
	})
	client := &fakeAIClient{}
	stubAIClient(t, client)
	payload := strimziPayload(t)
	payload.Config = &sdkconfig.Config{}

	result, message, confidence := AIReviewUncheckedControlEvidence(payload)

	if result != gemara.Failed || confidence != gemara.High || message != "[AI-Assisted] OSPS-SA-03.01 has no followable evidence" {
		t.Errorf("got %v %v %q", result, confidence, message)
	}
	golden := readFixture(t, "unchecked_control_evidence_prompt.golden", nil)
	if strings.TrimSuffix(string(golden), "\n") != client.prompt {
		t.Errorf("prompt differs from testdata/unchecked_control_evidence_prompt.golden:\n%s", client.prompt)
	}

	var packet uncheckedControlEvidence
	if err := json.Unmarshal([]byte(client.content), &packet); err != nil {
		t.Fatal(err)
	}
	if packet.PublishedResult.TargetPage != strimziPage || packet.PublishedResult.LogVersion != "1.3.0-20261025T171208Z" {
		t.Errorf("published result = %+v", packet.PublishedResult)
	}
	executed := map[string]bool{}
	for _, control := range packet.UncheckedControls {
		executed[control.ID] = control.Executed
	}
	// 4 Needs Review + 9 Not Run in the published counts; the log also lists
	// the controls the level-2 scan skipped.
	for id, want := range map[string]bool{"OSPS-BR-01.03": true, "OSPS-SA-03.01": true, "OSPS-BR-01.02": true, "OSPS-AC-04.02": false, "OSPS-VM-02.01": false} {
		if got, ok := executed[id]; !ok || got != want {
			t.Errorf("%s executed = %v (listed %v), want %v", id, got, ok, want)
		}
	}
	if _, ok := executed["OSPS-QA-03.01"]; ok {
		t.Error("failed control OSPS-QA-03.01 listed as unchecked")
	}
	// security-policy and vulnerability-reporting.policy are the same URL
	wantFetched := []string{
		"https://github.com/strimzi/.github/blob/main/SECURITY.md",
		"https://github.com/strimzi/strimzi-kafka-operator/blob/main/README.md#contributing",
		"https://github.com/strimzi/governance/blob/main/GOVERNANCE.md#pr-approval-rules",
		"https://github.com/strimzi/governance/blob/main/GOVERNANCE.md",
		"https://github.com/strimzi/strimzi-kafka-operator/blob/main/development-docs/DEV_GUIDE.md#dependency-management",
		"https://strimzi.io/docs/operators/latest/overview",
		"https://strimzi.io/documentation/",
		"https://strimzi.io/quickstarts/",
		"https://github.com/strimzi/strimzi-kafka-operator/blob/main/README.md#container-signatures",
	}
	if strings.Join(fetched, "\n") != strings.Join(wantFetched, "\n") {
		t.Errorf("fetched:\n%s\nwant:\n%s", strings.Join(fetched, "\n"), strings.Join(wantFetched, "\n"))
	}
	if packet.Documentation[0].Field != "repository.documentation.security-policy" || packet.Documentation[0].Content != "text of "+wantFetched[0] {
		t.Errorf("first document = %+v", packet.Documentation[0])
	}
	if packet.Documentation[5].Content != "Docs\nKafka & Kubernetes" {
		t.Errorf("HTML not reduced to text: %q", packet.Documentation[5].Content)
	}
	if packet.Collection.Complete || len(packet.Collection.Unretrieved) != 1 || packet.Collection.Unretrieved[0] != "https://strimzi.io/documentation/: HTTP 404" {
		t.Errorf("collection = %+v", packet.Collection)
	}
	evidence := payload.GetEvidence()
	if len(evidence) != 1 || !strings.Contains(evidence[0].Description, strimziPage) || strings.Contains(evidence[0].Description, "https://strimzi.io/documentation/") {
		t.Errorf("evidence = %+v", evidence)
	}
}

func Test_AIReviewUncheckedControlEvidence_NoAI(t *testing.T) {
	strimziHub(t).install(t)
	stubFetch(t, func(string) (data.FetchedURL, error) { return data.FetchedURL{StatusCode: 200}, nil })
	stubAIClient(t, nil)
	payload := strimziPayload(t)
	payload.Config = &sdkconfig.Config{}
	if result, _, _ := AIReviewUncheckedControlEvidence(payload); result != gemara.NeedsReview {
		t.Errorf("got %v, want NeedsReview when AI is not configured", result)
	}
}

func Test_AIReviewUncheckedControlEvidence_NothingUnchecked(t *testing.T) {
	h := strimziHub(t)
	h.log = []byte(`{"evaluations":[{"assessment-logs":[{"requirement":{"entry-id":"OSPS-AC-01.01"},"result":"Passed"}]}]}`)
	h.install(t)
	client := &fakeAIClient{}
	stubAIClient(t, client)
	payload := strimziPayload(t)
	payload.Config = &sdkconfig.Config{}
	if result, _, _ := AIReviewUncheckedControlEvidence(payload); result != gemara.Passed || client.calls != 0 {
		t.Errorf("got %v with %d AI calls, want Passed without AI", result, client.calls)
	}
}
