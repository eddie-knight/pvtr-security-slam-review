package mechanizer

import (
	"errors"
	"os"
	"testing"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
)

func ptrTo[T any](v T) *T { return &v }

func payloadWithTools(tools ...si.SecurityTool) data.Payload {
	return data.Payload{Insights: si.SecurityInsights{Repository: &si.Repository{
		SecurityPosture: si.SecurityPosture{Tools: tools},
	}}}
}

func Test_BaselineScannerListedInTools(t *testing.T) {
	// Strimzi's entry, verbatim
	strimzi := si.SecurityTool{
		Name:     "OSPS Baseline Scanner",
		Type:     "other",
		Rulesets: []string{"osps-baseline-2026-08"},
		Results: si.SecurityToolResults{CI: &si.Attestation{
			Name:         "OSPS Baseline evaluation",
			PredicateURI: "https://github.com/revanite-io/pvtr-publish-results",
			Location:     "https://grc.store/targets/strimzi/strimzi-kafka-operator",
		}},
	}
	codeql := si.SecurityTool{Name: "CodeQL", Rulesets: []string{"default"}, Results: si.SecurityToolResults{
		CI: &si.Attestation{PredicateURI: "https://github.com/github/codeql-action"},
	}}
	tests := []struct {
		name       string
		payload    data.Payload
		wantResult gemara.Result
		wantMsg    string
	}{
		{
			name:       "no tools",
			payload:    payloadWithTools(),
			wantResult: gemara.Failed,
			wantMsg:    "No OSPS Baseline scanner listed under repository.security.tools in Security Insights",
		},
		{
			name:       "only other tools",
			payload:    payloadWithTools(codeql),
			wantResult: gemara.Failed,
			wantMsg:    "No OSPS Baseline scanner listed under repository.security.tools in Security Insights",
		},
		{
			name:       "strimzi grc.store ci location",
			payload:    payloadWithTools(codeql, strimzi),
			wantResult: gemara.Passed,
			wantMsg:    "OSPS Baseline scanner listed in Security Insights tools: OSPS Baseline Scanner",
		},
		{
			name: "identified by predicate-uri only",
			payload: payloadWithTools(si.SecurityTool{Name: "Compliance", Results: si.SecurityToolResults{
				Release: &si.Attestation{PredicateURI: "https://github.com/revanite-io/osps-baseline-action"},
			}}),
			wantResult: gemara.Passed,
			wantMsg:    "OSPS Baseline scanner listed in Security Insights tools: Compliance",
		},
		{
			name: "adhoc result only",
			payload: payloadWithTools(si.SecurityTool{Name: "Privateer", Results: si.SecurityToolResults{
				Adhoc: &si.Attestation{Location: "https://example.com/report.html"},
			}}),
			wantResult: gemara.NeedsReview,
			wantMsg:    "OSPS Baseline scanner is listed in Security Insights tools, but a single ad hoc run is listed as the results location; Mechanizer needs a live, recurring scan: Privateer (adhoc result https://example.com/report.html)",
		},
		{
			name: "ci location is one workflow run",
			payload: payloadWithTools(si.SecurityTool{Name: "OSPS Baseline", Results: si.SecurityToolResults{
				CI: &si.Attestation{Location: "https://github.com/o/r/actions/runs/123456"},
			}}),
			wantResult: gemara.NeedsReview,
			wantMsg:    "OSPS Baseline scanner is listed in Security Insights tools, but a single ad hoc run is listed as the results location; Mechanizer needs a live, recurring scan: OSPS Baseline (https://github.com/o/r/actions/runs/123456)",
		},
		{
			name: "ad hoc entry alongside a recurring one passes",
			payload: payloadWithTools(si.SecurityTool{Name: "Privateer", Results: si.SecurityToolResults{
				Adhoc: &si.Attestation{Location: "https://github.com/o/r/actions/runs/1"},
			}}, strimzi),
			wantResult: gemara.Passed,
			wantMsg:    "OSPS Baseline scanner listed in Security Insights tools: OSPS Baseline Scanner",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, msg, _ := BaselineScannerListedInTools(tt.payload)
			if result != tt.wantResult || msg != tt.wantMsg {
				t.Errorf("got (%v, %q), want (%v, %q)", result, msg, tt.wantResult, tt.wantMsg)
			}
		})
	}
}

func stubWorkflows(t *testing.T, files []data.WorkflowFile, err error) {
	t.Helper()
	orig := getWorkflowFiles
	getWorkflowFiles = func(*data.Payload) ([]data.WorkflowFile, error) { return files, err }
	t.Cleanup(func() { getWorkflowFiles = orig })
}

func wf(path, content string) data.WorkflowFile {
	return data.WorkflowFile{Path: path, Content: []byte(content)}
}

const actionJob = `
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: revanite-io/osps-baseline-action@v1
`

func Test_ScannerWorkflows(t *testing.T) {
	strimzi, err := os.ReadFile("testdata/strimzi-osps-baseline.yml")
	if err != nil {
		t.Fatal(err)
	}
	unrelated := wf(".github/workflows/ci.yml", "on: push\njobs:\n  b:\n    steps:\n      - run: make\n")
	tests := []struct {
		name          string
		files         []data.WorkflowFile
		err           error
		wantRecurring gemara.Result
		wantRecMsg    string
		wantPRT       gemara.Result
		wantPRTMsg    string
	}{
		{
			name:          "strimzi reusable workflow caller",
			files:         []data.WorkflowFile{unrelated, wf(".github/workflows/osps-baseline.yml", string(strimzi))},
			wantRecurring: gemara.Passed,
			wantRecMsg:    "OSPS Baseline scanner workflow .github/workflows/osps-baseline.yml runs on push",
			wantPRT:       gemara.Passed,
			wantPRTMsg:    "OSPS Baseline scanner workflows do not trigger on pull_request_target: .github/workflows/osps-baseline.yml",
		},
		{
			name:          "no scanner workflow",
			files:         []data.WorkflowFile{unrelated},
			wantRecurring: gemara.Failed,
			wantRecMsg:    "No workflow on the default branch runs the OSPS Baseline scanner (osps-baseline-action or pvtr-publish-results)",
			wantPRT:       gemara.Failed,
			wantPRTMsg:    "No workflow on the default branch runs the OSPS Baseline scanner (osps-baseline-action or pvtr-publish-results)",
		},
		{
			name:          "string trigger release",
			files:         []data.WorkflowFile{wf("a.yml", "on: release"+actionJob)},
			wantRecurring: gemara.Passed,
			wantRecMsg:    "OSPS Baseline scanner workflow a.yml runs on release",
			wantPRT:       gemara.Passed,
			wantPRTMsg:    "OSPS Baseline scanner workflows do not trigger on pull_request_target: a.yml",
		},
		{
			name:          "list trigger, dispatch and pull_request only",
			files:         []data.WorkflowFile{wf("a.yml", "on: [workflow_dispatch, pull_request]"+actionJob)},
			wantRecurring: gemara.Failed,
			wantRecMsg:    "OSPS Baseline scanner workflow does not run on a schedule, push, or release: a.yml (pull_request, workflow_dispatch)",
			wantPRT:       gemara.Passed,
			wantPRTMsg:    "OSPS Baseline scanner workflows do not trigger on pull_request_target: a.yml",
		},
		{
			name:          "map trigger with pull_request_target and privateer run step",
			files:         []data.WorkflowFile{wf("a.yml", "on:\n  schedule:\n    - cron: '0 0 * * 0'\n  pull_request_target:\njobs:\n  s:\n    steps:\n      - run: privateer run -c config.yml\n")},
			wantRecurring: gemara.Passed,
			wantRecMsg:    "OSPS Baseline scanner workflow a.yml runs on schedule",
			wantPRT:       gemara.Failed,
			wantPRTMsg:    "OSPS Baseline scanner workflow triggers on pull_request_target: a.yml",
		},
		{
			name:          "unparseable workflow and no scanner",
			files:         []data.WorkflowFile{wf("bad.yml", "on: [push\njobs: {")},
			wantRecurring: gemara.NeedsReview,
			wantRecMsg:    "No OSPS Baseline scanner workflow found, but these workflows could not be parsed: bad.yml",
			wantPRT:       gemara.NeedsReview,
			wantPRTMsg:    "No OSPS Baseline scanner workflow found, but these workflows could not be parsed: bad.yml",
		},
		{
			name:          "workflows unreadable",
			err:           errors.New("boom"),
			wantRecurring: gemara.NeedsReview,
			wantRecMsg:    "Could not read workflows on the default branch: boom",
			wantPRT:       gemara.NeedsReview,
			wantPRTMsg:    "Could not read workflows on the default branch: boom",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubWorkflows(t, tt.files, tt.err)
			result, msg, _ := ScannerWorkflowRecurring(data.Payload{})
			if result != tt.wantRecurring || msg != tt.wantRecMsg {
				t.Errorf("recurring: got (%v, %q), want (%v, %q)", result, msg, tt.wantRecurring, tt.wantRecMsg)
			}
			result, msg, _ = ScannerWorkflowAvoidsPullRequestTarget(data.Payload{})
			if result != tt.wantPRT || msg != tt.wantPRTMsg {
				t.Errorf("pull_request_target: got (%v, %q), want (%v, %q)", result, msg, tt.wantPRT, tt.wantPRTMsg)
			}
		})
	}
}
