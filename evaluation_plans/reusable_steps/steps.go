package reusable_steps

import (
	"fmt"
	"maps"
	"strconv"
	"strings"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/gemaraproj/go-gemara"
	sdkai "github.com/privateerproj/privateer-sdk/ai"
	"github.com/privateerproj/privateer-sdk/config"
)

// NewAIClient builds the configured AI client; tests replace it.
var NewAIClient = newAIClient

// aiDefaults replace the SDK's 1024 tokens and 30s, which cut off a verdict
// that cites every control or reads 128K characters of documentation.
var aiDefaults = map[string]any{"ai_max_tokens": 4096, "ai_timeout": "120s"}

// newAIClient fills in aiDefaults the user left unset, but only once a
// provider is chosen, so an unconfigured run still reads as AI disabled.
func newAIClient(c config.Config) (sdkai.Client, error) {
	if c.GetString("ai_provider") != "" {
		vars := maps.Clone(c.Vars)
		for key, value := range aiDefaults {
			if _, set := vars[key]; !set {
				vars[key] = value
			}
		}
		c.Vars = vars
	}
	return sdkai.NewClient(c)
}

func NotImplemented(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	return gemara.NotRun, "Not implemented", confidence
}

// HasSecurityInsightsFile fails straight away when there is no usable
// Security Insights file: every badge's evidence is linked from it.
func HasSecurityInsightsFile(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.InsightsPath == "" {
		return gemara.Failed, "No Security Insights file found at the repository root", gemara.High
	}
	if payload.InsightsError != nil {
		return gemara.Failed, fmt.Sprintf("Security Insights file %s could not be parsed: %s", payload.InsightsPath, payload.InsightsError), gemara.High
	}
	return gemara.Passed, "Security Insights file found: " + payload.InsightsPath, gemara.High
}

// AIReview grades material against the behavior's rubric and records the
// model's verdict as evidence. It is always the last step of a badge, so it
// only runs once the deterministic steps found the evidence. With no AI
// provider configured it returns NeedsReview: the evidence exists, but nobody
// has judged its quality. sources name what the material was built from.
func AIReview(payload data.Payload, behavior string, material string, sources []string) (gemara.Result, string, gemara.ConfidenceLevel) {
	if payload.Config == nil {
		return gemara.NeedsReview, "AI review skipped: no plugin configuration; manual review needed", gemara.Low
	}
	client, err := NewAIClient(*payload.Config)
	if err != nil {
		return AIFallback(payload, behavior, "AI review was requested but the AI client could not be constructed; manual review needed", "AI client construction failed", err)
	}
	if client == nil {
		return gemara.NeedsReview, "AI review not configured (set ai_provider, ai_model, and ai_api_key); manual review needed", gemara.Low
	}
	response, evidence, err := RunAIAssessment(client, behavior, material)
	if err != nil {
		return AIFallback(payload, behavior, "AI review did not complete; manual review needed", "AI assessment failed", err)
	}
	if err := ValidateAIResponse(response); err != nil {
		return AIFallback(payload, behavior, "AI review returned a response that did not conform to the expected verdict schema; manual review needed", "AI response did not conform to the expected verdict schema", err)
	}
	if len(sources) > 0 {
		evidence.Description = "AI Assisted Review of " + strings.Join(sources, ", ")
	}
	payload.AddEvidence(evidence)
	// A low-confidence verdict means the model lacked evidence; it must not award or deny a badge.
	if response.GemaraResult() == gemara.NeedsReview || response.GemaraConfidence() == gemara.Low {
		return gemara.NeedsReview, response.Summary(), gemara.Low
	}
	return response.GemaraResult(), response.Summary(), response.GemaraConfidence()
}

// AIFallback logs why an AI-assisted assessment was abandoned and returns
// NeedsReview with the supplied fallback message.
func AIFallback(payload data.Payload, behavior string, fallbackMessage string, reason string, err error) (gemara.Result, string, gemara.ConfidenceLevel) {
	if payload.Config != nil && payload.Config.Logger != nil {
		payload.Config.Logger.Warn(behavior+": "+reason, "err", err)
	}
	return gemara.NeedsReview, fallbackMessage, gemara.Low
}

// ValidateAIResponse rejects responses that do not conform to the SDK's
// assessment schema before a plugin records or acts on them.
func ValidateAIResponse(response sdkai.Response) error {
	switch response.Result {
	case "pass", "fail", "needs_review":
	default:
		return fmt.Errorf("AI response result is invalid")
	}

	switch response.Confidence {
	case "low", "medium", "high":
	default:
		return fmt.Errorf("AI response confidence is invalid")
	}

	if strings.TrimSpace(response.Message) == "" {
		return fmt.Errorf("AI response message is required")
	}
	if strings.TrimSpace(response.Explanation) == "" {
		return fmt.Errorf("AI response explanation is required")
	}
	return nil
}

// MaturityLevelMissing is the message for steps that need maturity_level.
const MaturityLevelMissing = "Set the maturity_level var (1-3) to the project's OSPS Baseline maturity level"

// MaturityLevel reads the maturity_level var as an int or a numeric string.
func MaturityLevel(payload data.Payload) (int, bool) {
	if payload.Config == nil {
		return 0, false
	}
	value, _ := payload.Config.GetVar("maturity_level")
	var level int
	switch v := value.(type) {
	case int:
		level = v
	case float64:
		level = int(v)
	case string:
		level, _ = strconv.Atoi(strings.TrimSpace(v))
	}
	return level, level >= 1 && level <= 3
}
