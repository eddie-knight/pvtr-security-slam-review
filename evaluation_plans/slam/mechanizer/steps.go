package mechanizer

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/gemaraproj/go-gemara"
	"github.com/goccy/go-yaml"
	"github.com/ossf/si-tooling/v2/si"
)

// scannerMarkers identify the OSPS Baseline scanner in a Security Insights
// tool entry (name, comment, rulesets, predicate-uri, or location).
var scannerMarkers = []string{
	"osps baseline",
	"osps-baseline",
	"pvtr-publish-results",
	"pvtr-github-repo-scanner",
	"privateer",
}

// Test hooks: the default branch's workflows, the remote reusable workflows
// they call, a workflow's recent runs, and the clock.
var (
	getWorkflowFiles = (*data.Payload).GetWorkflowFiles
	fetchURL         = (*data.Payload).FetchURL
	getWorkflowRuns  = (*data.Payload).GetWorkflowRuns
	now              = time.Now
)

// maxRunAge is how recent a run must be for the scan to count as live.
const maxRunAge = 30 * 24 * time.Hour

// scannerUses identify a `uses:` that runs the scanner: the reusable publish
// workflow (job-level), the action, or the scanner itself as an action or a
// docker:// image (step-level).
var scannerUses = []string{
	"revanite-io/osps-baseline-action",
	"revanite-io/pvtr-publish-results",
	"pvtr-github-repo-scanner",
}

// scannerRuns identify a `run:` script that runs the scanner: the scanner's
// container image, or the privateer/pvtr CLI.
var scannerRuns = []string{
	"pvtr-github-repo-scanner",
	"privateer run",
	"pvtr run",
}

// recurringTriggers match the badge page: a schedule, or every push or release
// to the default branch. workflow_dispatch and pull_request alone are not live.
var recurringTriggers = []string{"schedule", "push", "release"}

var singleRunURL = regexp.MustCompile(`/actions/runs/\d+`)

func BaselineScannerListedInTools(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	for _, tool := range payload.Insights.Repository.SecurityPosture.Tools {
		if isScannerTool(tool) {
			if _, single := singleRunLocation(tool.Results); !single {
				return gemara.Passed, "OSPS Baseline scanner listed in Security Insights tools: " + tool.Name, gemara.High
			}
		}
	}
	if adhoc := adhocOnlyTool(payload); adhoc != "" {
		return gemara.NeedsReview, "OSPS Baseline scanner is listed in Security Insights tools, but a single ad hoc run is listed as the results location; Mechanizer needs a live, recurring scan: " + adhoc, gemara.Medium
	}
	return gemara.Failed, "No OSPS Baseline scanner listed under repository.security.tools in Security Insights", gemara.High
}

// adhocOnlyTool names the scanner entry and its single-run location when
// every scanner entry in Security Insights points at one past run, else "".
func adhocOnlyTool(payload data.Payload) string {
	if payload.Insights.Repository == nil {
		return ""
	}
	var adhoc string
	for _, tool := range payload.Insights.Repository.SecurityPosture.Tools {
		if !isScannerTool(tool) {
			continue
		}
		location, single := singleRunLocation(tool.Results)
		if !single {
			return ""
		}
		if adhoc == "" {
			adhoc = fmt.Sprintf("%s (%s)", tool.Name, location)
		}
	}
	return adhoc
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

// ScannerWorkflowRequirements reports every workflow requirement in one
// message, because an assessment keeps only its last step's message: the
// workflow and step that run the scanner, a recurring trigger on the default
// branch, and a recent run from that trigger. It repeats the ad hoc results
// warning from BaselineScannerListedInTools for the same reason.
func ScannerWorkflowRequirements(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	workflows, result, message := scannerWorkflows(payload)
	if workflows == nil {
		return result, message, gemara.High
	}
	var matched, recurring, notRecurring []string
	var live []scannerWorkflow
	for _, wf := range workflows {
		matched = append(matched, wf.path+" ("+wf.match+")")
		if fired := liveTriggers(wf.on, payload.DefaultBranch); len(fired) > 0 {
			recurring = append(recurring, wf.path+" on "+strings.Join(fired, ", "))
			live = append(live, wf)
		} else {
			notRecurring = append(notRecurring, fmt.Sprintf("%s (%s)", wf.path, strings.Join(triggers(wf.on), ", ")))
		}
	}
	result = gemara.Passed
	report := []string{"Scanner runs in " + strings.Join(matched, "; ")}
	if len(live) == 0 {
		result = gemara.Failed
		report = append(report, "FAIL recurring trigger: no schedule, or push or release on the default branch, in "+strings.Join(notRecurring, "; "))
	} else {
		report = append(report, "PASS recurring trigger: "+strings.Join(recurring, "; "))
		runResult, runReport := recentRuns(payload, live)
		result = gemara.UpdateAggregateResult(result, runResult)
		report = append(report, runReport)
	}
	if adhoc := adhocOnlyTool(payload); adhoc != "" {
		if result == gemara.Passed {
			result = gemara.NeedsReview
		}
		report = append(report, "WARN Security Insights lists a single ad hoc run as the scanner's results location instead of the recurring workflow: "+adhoc)
	} else if runs := singleRunAttestations(payload); len(runs) > 0 {
		report = append(report, "WARN Security Insights also lists a single one-off run as a scanner results location: "+strings.Join(runs, ", "))
	}
	return result, strings.Join(report, ". "), gemara.High
}

// singleRunAttestations lists the scanner results locations that are one past
// run (an adhoc result, or a link to a single workflow run), even when a
// recurring location is listed beside them.
func singleRunAttestations(payload data.Payload) []string {
	if payload.Insights.Repository == nil {
		return nil
	}
	var runs []string
	for _, tool := range payload.Insights.Repository.SecurityPosture.Tools {
		if !isScannerTool(tool) {
			continue
		}
		for _, a := range attestations(tool.Results) {
			if a == tool.Results.Adhoc || singleRunURL.MatchString(string(a.Location)) {
				runs = append(runs, fmt.Sprintf("%s (%s)", tool.Name, a.Location))
			}
		}
	}
	return runs
}

type scannerWorkflow struct {
	path  string
	on    any    // the workflow's `on:`
	match string // the job and step that run the scanner
}

// recentRuns requires a run of a recurring scanner workflow, started by one of
// its recurring triggers on the default branch, within maxRunAge: a disabled
// workflow, or a schedule GitHub switched off, has a trigger but no runs. A
// failing run still counts, since the badge asks for a scan, not a pass.
func recentRuns(payload data.Payload, workflows []scannerWorkflow) (gemara.Result, string) {
	var recent, stale, unreadable []string
	for _, wf := range workflows {
		runs, err := getWorkflowRuns(&payload, wf.path)
		if err != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s: %s", wf.path, err))
			continue
		}
		var last *data.WorkflowRun
		for i, run := range runs {
			if run.Status == "completed" && slices.Contains(recurringTriggers, run.Event) && (last == nil || run.CreatedAt.After(last.CreatedAt)) {
				last = &runs[i]
			}
		}
		switch {
		case last == nil:
			stale = append(stale, wf.path+" has no completed run from a recurring trigger")
		case now().Sub(last.CreatedAt) > maxRunAge:
			stale = append(stale, fmt.Sprintf("%s last ran %s", wf.path, last.CreatedAt.Format(time.DateOnly)))
		default:
			recent = append(recent, fmt.Sprintf("%s ran %s (%s, %s) %s", wf.path, last.CreatedAt.Format(time.DateOnly), last.Event, last.Conclusion, last.URL))
		}
	}
	days := int(maxRunAge.Hours() / 24)
	switch {
	case len(recent) > 0:
		return gemara.Passed, fmt.Sprintf("PASS run in the last %d days: %s", days, strings.Join(recent, "; "))
	case len(unreadable) > 0:
		return gemara.NeedsReview, "WARN could not read workflow runs: " + strings.Join(append(unreadable, stale...), "; ")
	}
	return gemara.Failed, fmt.Sprintf("FAIL run in the last %d days: %s", days, strings.Join(stale, "; "))
}

// liveTriggers lists the recurring triggers that fire for the default branch:
// a schedule always does; push only when its branch filters admit the default
// branch; release always does. With no default branch known, filters are not
// applied.
func liveTriggers(on any, defaultBranch string) []string {
	var live []string
	filters, _ := on.(map[string]any)
	for _, trigger := range triggers(on) {
		if !slices.Contains(recurringTriggers, trigger) {
			continue
		}
		if trigger == "push" && defaultBranch != "" && !pushReaches(filters["push"], defaultBranch) {
			continue
		}
		live = append(live, trigger)
	}
	return live
}

// pushReaches applies a push trigger's branches / branches-ignore filters.
// A push filtered only by tags or paths does not run on branch pushes unless
// branches is also given, matching GitHub.
// shortcut: path.Match, not GitHub's full glob syntax (**, !negation); widen if a project's filter is misread.
func pushReaches(config any, branch string) bool {
	filters, _ := config.(map[string]any)
	matches := func(key string) (bool, bool) {
		patterns, ok := filters[key].([]any)
		if !ok {
			return false, false
		}
		for _, p := range patterns {
			if ok, _ := path.Match(fmt.Sprint(p), branch); ok {
				return true, true
			}
		}
		return false, true
	}
	if hit, set := matches("branches"); set {
		return hit
	}
	if hit, set := matches("branches-ignore"); set {
		return !hit
	}
	_, tagsOnly := filters["tags"]
	return !tagsOnly
}

// workflowFile holds only the fields these steps read.
type workflowFile struct {
	On   any                    `yaml:"on"`
	Jobs map[string]workflowJob `yaml:"jobs"`
}

type workflowJob struct {
	Uses  string `yaml:"uses"`
	Steps []struct {
		Name string `yaml:"name"`
		Uses string `yaml:"uses"`
		Run  string `yaml:"run"`
	} `yaml:"steps"`
}

// scannerWorkflows returns the default branch's workflows that run the
// scanner. When there are none it returns nil plus the step's verdict: Failed,
// or NeedsReview if a workflow could not be read or parsed.
func scannerWorkflows(payload data.Payload) ([]scannerWorkflow, gemara.Result, string) {
	files, err := getWorkflowFiles(&payload)
	if err != nil {
		return nil, gemara.NeedsReview, fmt.Sprintf("Could not read workflows on the default branch: %s", err)
	}
	var parsed []data.WorkflowFile
	var unparsed []string
	workflows := map[string]workflowFile{}
	match := map[string]string{}
	for _, file := range files {
		var wf workflowFile
		if err := yaml.Unmarshal(file.Content, &wf); err != nil {
			unparsed = append(unparsed, file.Path)
			continue
		}
		parsed = append(parsed, file)
		workflows[file.Path] = wf
		match[file.Path] = scannerMatch(&payload, wf, true)
	}
	// A workflow that calls a local scanner workflow runs the scanner too.
	for changed := true; changed; {
		changed = false
		for path, wf := range workflows {
			if match[path] != "" {
				continue
			}
			for _, name := range jobNames(wf) {
				if called, ok := strings.CutPrefix(wf.Jobs[name].Uses, "./"); ok && match[called] != "" {
					match[path], changed = fmt.Sprintf("job %s calls %s, where %s", name, called, match[called]), true
					break
				}
			}
		}
	}
	var found []scannerWorkflow
	for _, file := range parsed {
		if match[file.Path] == "" {
			continue
		}
		wf := workflows[file.Path]
		// A workflow_call-only workflow is judged by its callers' triggers.
		if slices.Equal(triggers(wf.On), []string{"workflow_call"}) && hasCaller(workflows, file.Path) {
			continue
		}
		found = append(found, scannerWorkflow{path: file.Path, on: wf.On, match: match[file.Path]})
	}
	if len(found) > 0 {
		return found, gemara.Passed, ""
	}
	if len(unparsed) > 0 {
		return nil, gemara.NeedsReview, "No OSPS Baseline scanner workflow found, but these workflows could not be parsed: " + strings.Join(unparsed, ", ")
	}
	return nil, gemara.Failed, "No workflow on the default branch runs the OSPS Baseline scanner (osps-baseline-action, pvtr-publish-results, the pvtr-github-repo-scanner action or image, or the privateer/pvtr CLI)"
}

// localCalls lists the repository workflows the jobs call with a local
// `uses: ./.github/workflows/x.yml`.
func localCalls(wf workflowFile) []string {
	var called []string
	for _, name := range jobNames(wf) {
		if path, ok := strings.CutPrefix(wf.Jobs[name].Uses, "./"); ok {
			called = append(called, path)
		}
	}
	return called
}

func hasCaller(workflows map[string]workflowFile, path string) bool {
	for _, wf := range workflows {
		if slices.Contains(localCalls(wf), path) {
			return true
		}
	}
	return false
}

func jobNames(wf workflowFile) []string {
	names := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// scannerMatch names the job and step that run the scanner, or "". With
// followRemote it also reads a remote reusable workflow a job calls, one
// level deep, since the scanner can sit inside an organization's shared
// workflow.
func scannerMatch(payload *data.Payload, wf workflowFile, followRemote bool) string {
	contains := func(text string, markers []string) bool {
		text = strings.ToLower(text)
		return slices.ContainsFunc(markers, func(m string) bool { return strings.Contains(text, m) })
	}
	for _, name := range jobNames(wf) {
		job := wf.Jobs[name]
		if contains(job.Uses, scannerUses) {
			return fmt.Sprintf("job %s uses %s", name, job.Uses)
		}
		for i, step := range job.Steps {
			label := step.Name
			if label == "" {
				label = fmt.Sprintf("#%d", i+1)
			}
			if contains(step.Uses, scannerUses) {
				return fmt.Sprintf("job %s step %s uses %s", name, label, step.Uses)
			}
			if contains(step.Run, scannerRuns) {
				return fmt.Sprintf("job %s step %s runs the scanner", name, label)
			}
		}
	}
	if !followRemote {
		return ""
	}
	for _, name := range jobNames(wf) {
		uses := wf.Jobs[name].Uses
		repo, rest, ok := strings.Cut(uses, "/.github/workflows/")
		if !ok || strings.HasPrefix(uses, "./") {
			continue
		}
		file, ref, ok := strings.Cut(rest, "@")
		if !ok {
			continue
		}
		fetched, err := fetchURL(payload, fmt.Sprintf("https://github.com/%s/blob/%s/.github/workflows/%s", repo, ref, file))
		if err != nil || fetched.StatusCode != 200 {
			continue
		}
		var remote workflowFile
		if yaml.Unmarshal(fetched.Body, &remote) != nil {
			continue
		}
		if inner := scannerMatch(payload, remote, false); inner != "" {
			return fmt.Sprintf("job %s calls %s, where %s", name, uses, inner)
		}
	}
	return ""
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
