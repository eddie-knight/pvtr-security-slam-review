package reusable_steps

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/gemaraproj/go-gemara"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
	sdkconfig "github.com/privateerproj/privateer-sdk/config"
)

type fakeAIClient struct{ body string }

func (c fakeAIClient) Analyze(context.Context, string, string, *sdkai.Schema) (*sdkai.AnalyzeResponse, error) {
	return &sdkai.AnalyzeResponse{JSON: json.RawMessage(c.body)}, nil
}

func TestNewAIClientDefaults(t *testing.T) {
	client, err := newAIClient(sdkconfig.Config{Vars: map[string]any{"owner": "o"}})
	if client != nil || err != nil {
		t.Fatalf("unconfigured AI: got %v, %v; want nil, nil", client, err)
	}

	vars := map[string]any{"ai_provider": "anthropic", "ai_model": "m", "ai_api_key": "k"}
	client, err = newAIClient(sdkconfig.Config{Vars: vars})
	if client == nil || err != nil {
		t.Fatalf("configured AI: got %v, %v", client, err)
	}
	if _, set := vars["ai_max_tokens"]; set {
		t.Error("defaults leaked into the caller's vars")
	}
}

func TestAIReviewLowConfidenceNeedsReview(t *testing.T) {
	original := NewAIClient
	t.Cleanup(func() { NewAIClient = original })
	payload := data.Payload{Config: &sdkconfig.Config{}, Evidence: &gemara.EvidenceCollector{}}

	for verdict, want := range map[string]gemara.Result{
		"pass":   gemara.NeedsReview,
		"fail":   gemara.NeedsReview,
		"medium": gemara.Passed,
	} {
		result, confidence := verdict, "low"
		if verdict == "medium" {
			result, confidence = "pass", "medium"
		}
		body := `{"result":"` + result + `","confidence":"` + confidence + `","message":"m","explanation":"e"}`
		NewAIClient = func(sdkconfig.Config) (sdkai.Client, error) { return fakeAIClient{body}, nil }
		got, _, _ := AIReview(payload, "chronicler-documentation-quality", "{}", nil)
		if got != want {
			t.Errorf("%s/%s: got %s, want %s", result, confidence, got, want)
		}
	}
}
