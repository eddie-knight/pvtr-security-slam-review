package chronicler

import (
	"fmt"
	"strings"
	"sync"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/reusable_steps"
	"github.com/gemaraproj/go-gemara"
	scannerdata "github.com/ossf/pvtr-github-repo-scanner/data"
	scanner "github.com/ossf/pvtr-github-repo-scanner/evaluation_plans"
)

// Test hooks: the scanner's loader makes its own GitHub API calls.
var (
	loadScanner  = scannerdata.Loader
	scannerSteps = scanner.OSPS
)

// documentationControls are the OSPS Baseline documentation-shaped controls
// (the DO family, and the GV and VM controls the Slam's chronicler guide
// counts) with the lowest maturity level each applies at.
// shortcut: levels copied from the scanner's OSPS_Baseline_2026_08 catalog, which it embeds in package main; update when the Baseline moves a control.
var documentationControls = []struct {
	id    string
	level int
}{
	{"OSPS-DO-01.01", 1},
	{"OSPS-DO-02.01", 1},
	{"OSPS-GV-03.01", 1},
	{"OSPS-VM-02.01", 1},
	{"OSPS-DO-06.01", 2},
	{"OSPS-DO-07.01", 2},
	{"OSPS-GV-01.01", 2},
	{"OSPS-GV-01.02", 2},
	{"OSPS-GV-03.02", 2},
	{"OSPS-VM-01.01", 2},
	{"OSPS-VM-03.01", 2},
	{"OSPS-VM-04.01", 2},
	{"OSPS-DO-03.01", 3},
	{"OSPS-DO-03.02", 3},
	{"OSPS-DO-04.01", 3},
	{"OSPS-DO-05.01", 3},
	{"OSPS-GV-04.01", 3},
	{"OSPS-VM-05.01", 3},
	{"OSPS-VM-05.02", 3},
	{"OSPS-VM-06.01", 3},
}

// BaselineDocumentationControlsMet runs the OSPS Baseline scanner's own steps
// for every documentation-shaped control at the project's maturity level.
func BaselineDocumentationControlsMet(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	baselineNotes.Delete(noteKey(payload))
	level, ok := reusable_steps.MaturityLevel(payload)
	if !ok {
		return gemara.NeedsReview, reusable_steps.MaturityLevelMissing, gemara.Low
	}
	if payload.Config == nil {
		return gemara.NeedsReview, "No plugin configuration to load the OSPS Baseline scanner's repository data", gemara.Low
	}
	// Name the scanner's logger so its own warnings (e.g. two Security
	// Insights files, which Cleaner reports) do not print as bare lines.
	scanConfig := *payload.Config
	if scanConfig.Logger != nil {
		scanConfig.Logger = scanConfig.Logger.Named("SLAM-CH-01.01 osps-baseline-scanner")
	}
	loaded, err := loadScanner(&scanConfig)
	if err != nil {
		return gemara.NeedsReview, "Could not load the OSPS Baseline scanner's repository data: " + err.Error(), gemara.Low
	}
	scan, ok := loaded.(scannerdata.Payload)
	if !ok {
		return gemara.NeedsReview, fmt.Sprintf("The OSPS Baseline scanner loader returned %T", loaded), gemara.Low
	}

	var failed, unresolved []string
	for _, control := range documentationControls {
		if control.level > level {
			continue
		}
		controlResult, controlMessage := runScannerSteps(scan, scannerSteps[control.id])
		switch controlResult {
		case gemara.Failed:
			failed = append(failed, control.id+": "+controlMessage)
		case gemara.NeedsReview, gemara.Unknown, gemara.NotRun:
			unresolved = append(unresolved, control.id+": "+controlMessage)
		}
	}
	switch {
	case len(failed) > 0:
		return gemara.Failed, fmt.Sprintf("OSPS Baseline documentation controls at maturity level %d not met: %s", level, strings.Join(failed, "; ")), gemara.High
	case len(unresolved) > 0:
		// Eddie's ruling: controls the scanner cannot decide do not block
		// Chronicler; they are reported with the AI verdict instead.
		note := fmt.Sprintf("OSPS Baseline documentation controls at maturity level %d need review (this does not block Chronicler): %s", level, strings.Join(unresolved, "; "))
		baselineNotes.Store(noteKey(payload), note)
		return gemara.Passed, note, gemara.Medium
	}
	return gemara.Passed, fmt.Sprintf("Every OSPS Baseline documentation control at maturity level %d passed the scanner's checks", level), gemara.High
}

// baselineNotes carries a target's Needs Review notes from the Baseline step
// to the AI step, whose message is the only one the log keeps.
var baselineNotes sync.Map

func noteKey(payload data.Payload) string {
	return payload.Owner + "/" + payload.Repo + "@" + payload.Commit
}

// runScannerSteps mirrors how gemara runs a control's steps: results
// aggregate, a Failed step stops the control, and a Not Applicable step
// settles it.
func runScannerSteps(scan scannerdata.Payload, steps []scanner.TypedStep) (gemara.Result, string) {
	if len(steps) == 0 {
		return gemara.NotRun, "the scanner has no steps for this control"
	}
	result, message := gemara.NotRun, ""
	for _, step := range steps {
		stepResult, stepMessage, _ := step(scan)
		switch stepResult {
		case gemara.Failed:
			return gemara.Failed, stepMessage
		case gemara.NotApplicable:
			return gemara.NotApplicable, stepMessage
		}
		result = gemara.UpdateAggregateResult(result, stepResult)
		message = stepMessage
	}
	return result, message
}
