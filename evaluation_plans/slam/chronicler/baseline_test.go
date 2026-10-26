package chronicler

import (
	"errors"
	"strings"
	"testing"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/gemaraproj/go-gemara"
	scannerdata "github.com/ossf/pvtr-github-repo-scanner/data"
	scanner "github.com/ossf/pvtr-github-repo-scanner/evaluation_plans"
	sdkconfig "github.com/privateerproj/privateer-sdk/config"
)

func TestDocumentationControlsExistInScanner(t *testing.T) {
	for _, control := range documentationControls {
		if len(scanner.OSPS[control.id]) == 0 {
			t.Errorf("scanner has no steps for %s", control.id)
		}
	}
}

func step(result gemara.Result, message string) scanner.TypedStep {
	return func(scannerdata.Payload) (gemara.Result, string, gemara.ConfidenceLevel) {
		return result, message, gemara.High
	}
}

func stubScanner(t *testing.T, err error, steps map[string][]scanner.TypedStep) {
	t.Helper()
	originalLoad, originalSteps := loadScanner, scannerSteps
	t.Cleanup(func() { loadScanner, scannerSteps = originalLoad, originalSteps })
	loadScanner = func(*sdkconfig.Config) (any, error) { return scannerdata.Payload{}, err }
	scannerSteps = steps
}

func TestBaselineDocumentationControlsMet(t *testing.T) {
	pass := step(gemara.Passed, "ok")
	allPass := map[string][]scanner.TypedStep{}
	for _, control := range documentationControls {
		allPass[control.id] = []scanner.TypedStep{pass}
	}
	with := func(id string, steps ...scanner.TypedStep) map[string][]scanner.TypedStep {
		m := map[string][]scanner.TypedStep{}
		for k, v := range allPass {
			m[k] = v
		}
		m[id] = steps
		return m
	}

	tests := []struct {
		name    string
		level   any
		loadErr error
		steps   map[string][]scanner.TypedStep
		want    gemara.Result
		inMsg   string
	}{
		{"missing level", nil, nil, allPass, gemara.NeedsReview, "maturity_level"},
		{"loader error", 1, errors.New("boom"), allPass, gemara.NeedsReview, "boom"},
		{"all pass", 3, nil, allPass, gemara.Passed, "level 3"},
		{"level 3 control ignored at level 1", 1, nil, with("OSPS-DO-04.01", step(gemara.Failed, "no support")), gemara.Passed, ""},
		{"level 3 control counted at level 3", 3, nil, with("OSPS-DO-04.01", step(gemara.Failed, "no support")), gemara.Failed, "OSPS-DO-04.01: no support"},
		{"failed step stops the control", 1, nil, with("OSPS-DO-01.01", step(gemara.Failed, "no SI"), pass), gemara.Failed, "OSPS-DO-01.01: no SI"},
		{"not applicable settles the control", 2, nil, with("OSPS-DO-06.01", step(gemara.NotApplicable, "not code"), step(gemara.Failed, "x")), gemara.Passed, ""},
		// Needs Review alone does not block Chronicler (Eddie's 23:15 ruling).
		{"needs review", 1, nil, with("OSPS-DO-02.01", step(gemara.NeedsReview, "unclear")), gemara.Passed, "need review (this does not block Chronicler): OSPS-DO-02.01: unclear"},
		{"failure beside needs review still fails", 1, nil, with("OSPS-DO-02.01", step(gemara.Failed, "missing")), gemara.Failed, "OSPS-DO-02.01: missing"},
	}
	t.Cleanup(func() { baselineNotes.Clear() })
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubScanner(t, tt.loadErr, tt.steps)
			vars := map[string]any{}
			if tt.level != nil {
				vars["maturity_level"] = tt.level
			}
			got, msg, _ := BaselineDocumentationControlsMet(data.Payload{Config: &sdkconfig.Config{Vars: vars}})
			if got != tt.want || !strings.Contains(msg, tt.inMsg) {
				t.Errorf("got %s %q; want %s containing %q", got, msg, tt.want, tt.inMsg)
			}
		})
	}
}

// With the Baseline step at Needs Review only and the AI passing, Chronicler
// passes, and the AI step's message, the one the log keeps, carries the notes.
func TestChroniclerPassesOverBaselineNeedsReview(t *testing.T) {
	t.Cleanup(func() { baselineNotes.Clear() })
	pass := step(gemara.Passed, "ok")
	steps := map[string][]scanner.TypedStep{}
	for _, control := range documentationControls {
		steps[control.id] = []scanner.TypedStep{pass}
	}
	steps["OSPS-DO-02.01"] = []scanner.TypedStep{step(gemara.NeedsReview, "unclear")}
	stubScanner(t, nil, steps)
	stubFetch(t, okFetch)
	stubAIClient(t, &fakeAIClient{body: `{"result":"pass","confidence":"high","message":"ok","explanation":"All documents are real."}`})
	payload := newPayload()
	payload.Config.Vars = map[string]any{"maturity_level": 1}

	baseline, _, _ := BaselineDocumentationControlsMet(payload)
	ai, message, _ := AIReviewDocumentation(payload)

	if got := gemara.UpdateAggregateResult(baseline, ai); got != gemara.Passed {
		t.Errorf("Chronicler = %v, want Passed", got)
	}
	if !strings.Contains(message, "[Baseline step: OSPS Baseline documentation controls at maturity level 1 need review (this does not block Chronicler): OSPS-DO-02.01: unclear]") {
		t.Errorf("AI message lacks the Baseline notes: %q", message)
	}
}
