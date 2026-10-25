package mechanizer

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/gemaraproj/go-gemara"
	"github.com/goccy/go-yaml"
	"github.com/ossf/si-tooling/v2/si"
)

// getWorkflowFiles is a test hook for the default branch's workflows.
var getWorkflowFiles = (*data.Payload).GetWorkflowFiles

// scannerMarkers identify the OSPS Baseline scanner in a Security Insights
// tool entry (name, comment, rulesets, predicate-uri, or location).
var scannerMarkers = []string{
	"osps baseline",
	"osps-baseline",
	"pvtr-publish-results",
	"pvtr-github-repo-scanner",
	"privateer",
}

// scannerUses identify a workflow that runs the scanner: the reusable publish
// workflow (job-level uses), the action, or the scanner itself (step-level).
var scannerUses = []string{
	"revanite-io/osps-baseline-action",
	"revanite-io/pvtr-publish-results",
	"ossf/pvtr-github-repo-scanner",
}

// recurringTriggers match the badge page: a schedule, or every push or release
// to the default branch. workflow_dispatch and pull_request alone are not live.
var recurringTriggers = []string{"schedule", "push", "release"}

var singleRunURL = regexp.MustCompile(`/actions/runs/\d+`)

func BaselineScannerListedInTools(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	var adhocOnly string
	for _, tool := range payload.Insights.Repository.SecurityPosture.Tools {
		if !isScannerTool(tool) {
			continue
		}
		if location, single := singleRunLocation(tool.Results); single {
			adhocOnly = fmt.Sprintf("%s (%s)", tool.Name, location)
			continue
		}
		return gemara.Passed, "OSPS Baseline scanner listed in Security Insights tools: " + tool.Name, gemara.High
	}
	if adhocOnly != "" {
		return gemara.NeedsReview, "OSPS Baseline scanner is listed in Security Insights tools, but a single ad hoc run is listed as the results location; Mechanizer needs a live, recurring scan: " + adhocOnly, gemara.Medium
	}
	return gemara.Failed, "No OSPS Baseline scanner listed under repository.security.tools in Security Insights", gemara.High
}

func isScannerTool(tool si.SecurityTool) bool {
	fields := append([]string{tool.Name}, tool.Rulesets...)
	if tool.Comment != nil {
		fields = append(fields, *tool.Comment)
	}
	for _, a := range attestations(tool.Results) {
		fields = append(fields, a.Name, a.PredicateURI, string(a.Location))
	}
	text := strings.ToLower(strings.Join(fields, "\n"))
	return slices.ContainsFunc(scannerMarkers, func(m string) bool { return strings.Contains(text, m) })
}

func attestations(results si.SecurityToolResults) []*si.Attestation {
	var all []*si.Attestation
	for _, a := range []*si.Attestation{results.CI, results.Release, results.Adhoc} {
		if a != nil {
			all = append(all, a)
		}
	}
	return all
}

// singleRunLocation reports whether the only results the entry points to are
// one past run: an adhoc result with no ci or release result, or locations
// that all link a single workflow run.
func singleRunLocation(results si.SecurityToolResults) (string, bool) {
	all := attestations(results)
	if len(all) == 0 {
		return "", false
	}
	if results.CI == nil && results.Release == nil {
		return "adhoc result " + string(results.Adhoc.Location), true
	}
	for _, a := range all {
		if !singleRunURL.MatchString(string(a.Location)) {
			return "", false
		}
	}
	return string(all[0].Location), true
}

func ScannerWorkflowRecurring(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	workflows, result, message := scannerWorkflows(payload)
	if workflows == nil {
		return result, message, gemara.High
	}
	var found []string
	for _, wf := range workflows {
		for _, trigger := range wf.triggers {
			if slices.Contains(recurringTriggers, trigger) {
				return gemara.Passed, fmt.Sprintf("OSPS Baseline scanner workflow %s runs on %s", wf.path, trigger), gemara.High
			}
		}
		found = append(found, fmt.Sprintf("%s (%s)", wf.path, strings.Join(wf.triggers, ", ")))
	}
	return gemara.Failed, "OSPS Baseline scanner workflow does not run on a schedule, push, or release: " + strings.Join(found, "; "), gemara.High
}

func ScannerWorkflowAvoidsPullRequestTarget(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	workflows, result, message := scannerWorkflows(payload)
	if workflows == nil {
		return result, message, gemara.High
	}
	var unsafe, paths []string
	for _, wf := range workflows {
		paths = append(paths, wf.path)
		if slices.Contains(wf.triggers, "pull_request_target") {
			unsafe = append(unsafe, wf.path)
		}
	}
	if len(unsafe) > 0 {
		return gemara.Failed, "OSPS Baseline scanner workflow triggers on pull_request_target: " + strings.Join(unsafe, ", "), gemara.High
	}
	return gemara.Passed, "OSPS Baseline scanner workflows do not trigger on pull_request_target: " + strings.Join(paths, ", "), gemara.High
}

type scannerWorkflow struct {
	path     string
	triggers []string
}

// workflowFile holds only the fields these steps read.
type workflowFile struct {
	On   any `yaml:"on"`
	Jobs map[string]struct {
		Uses  string `yaml:"uses"`
		Steps []struct {
			Uses string `yaml:"uses"`
			Run  string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// scannerWorkflows returns the default branch's workflows that run the
// scanner. When there are none it returns nil plus the step's verdict: Failed,
// or NeedsReview if a workflow could not be read or parsed.
func scannerWorkflows(payload data.Payload) ([]scannerWorkflow, gemara.Result, string) {
	files, err := getWorkflowFiles(&payload)
	if err != nil {
		return nil, gemara.NeedsReview, fmt.Sprintf("Could not read workflows on the default branch: %s", err)
	}
	var found []scannerWorkflow
	var unparsed []string
	for _, file := range files {
		var wf workflowFile
		if err := yaml.Unmarshal(file.Content, &wf); err != nil {
			unparsed = append(unparsed, file.Path)
			continue
		}
		if runsScanner(wf) {
			found = append(found, scannerWorkflow{path: file.Path, triggers: triggers(wf.On)})
		}
	}
	if len(found) > 0 {
		return found, gemara.Passed, ""
	}
	if len(unparsed) > 0 {
		return nil, gemara.NeedsReview, "No OSPS Baseline scanner workflow found, but these workflows could not be parsed: " + strings.Join(unparsed, ", ")
	}
	return nil, gemara.Failed, "No workflow on the default branch runs the OSPS Baseline scanner (osps-baseline-action or pvtr-publish-results)"
}

func runsScanner(wf workflowFile) bool {
	usesScanner := func(uses string) bool {
		uses = strings.ToLower(uses)
		return slices.ContainsFunc(scannerUses, func(m string) bool { return strings.Contains(uses, m) })
	}
	for _, job := range wf.Jobs {
		if usesScanner(job.Uses) {
			return true
		}
		for _, step := range job.Steps {
			if usesScanner(step.Uses) || strings.Contains(step.Run, "privateer run") {
				return true
			}
		}
	}
	return false
}

// triggers reads `on:` in any of its three forms: a string, a list, or a map.
func triggers(on any) []string {
	var names []string
	switch on := on.(type) {
	case string:
		names = append(names, on)
	case []any:
		for _, name := range on {
			names = append(names, fmt.Sprint(name))
		}
	case map[string]any:
		for name := range on {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}
