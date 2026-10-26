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

const (
	sha       = "0123456789abcdef0123456789abcdef01234567"
	actionJob = `
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@` + sha + `
      - name: Scan
        uses: revanite-io/osps-baseline-action@` + sha + `
`
)

func Test_ScannerWorkflowRequirements(t *testing.T) {
	strimzi, err := os.ReadFile("testdata/strimzi-osps-baseline.yml")
	if err != nil {
		t.Fatal(err)
	}
	unrelated := wf(".github/workflows/ci.yml", "on: push\njobs:\n  b:\n    steps:\n      - run: make\n")
	adhoc := payloadWithTools(si.SecurityTool{Name: "Privateer", Results: si.SecurityToolResults{
		Adhoc: &si.Attestation{Location: "https://github.com/o/r/actions/runs/1"},
	}})
	tests := []struct {
		name       string
		payload    data.Payload
		files      []data.WorkflowFile
		err        error
		remote     map[string]string
		wantResult gemara.Result
		wantMsg    string
	}{
		{
			name:       "strimzi calls pvtr-publish-results by tag, which is exempt from pinning",
			files:      []data.WorkflowFile{unrelated, wf(".github/workflows/osps-baseline.yml", string(strimzi))},
			wantResult: gemara.Passed,
			wantMsg:    "Scanner runs in .github/workflows/osps-baseline.yml (job results uses revanite-io/pvtr-publish-results/.github/workflows/publish.yml@v1). PASS recurring trigger: .github/workflows/osps-baseline.yml on push, schedule. PASS actions pinned to full commit SHAs. PASS no pull_request_target",
		},
		{
			name: "scheduled caller of a local workflow_call scanner workflow",
			files: []data.WorkflowFile{
				wf(".github/workflows/ci.yml", "on:\n  schedule:\n    - cron: '0 0 * * 0'\njobs:\n  baseline:\n    uses: ./.github/workflows/baseline.yml\n"),
				wf(".github/workflows/baseline.yml", "on: workflow_call"+actionJob),
			},
			wantResult: gemara.Passed,
			wantMsg:    "Scanner runs in .github/workflows/ci.yml (job baseline calls .github/workflows/baseline.yml, where job scan step Scan uses revanite-io/osps-baseline-action@" + sha + "). PASS recurring trigger: .github/workflows/ci.yml on schedule. PASS actions pinned to full commit SHAs. PASS no pull_request_target",
		},
		{
			name: "every requirement failing is reported, including the called workflow's tags",
			files: []data.WorkflowFile{
				wf("caller.yml", "on: [pull_request_target, workflow_dispatch]\njobs:\n  b:\n    uses: ./called.yml\n"),
				wf("called.yml", "on: workflow_call\njobs:\n  s:\n    steps:\n      - uses: actions/checkout@v5\n      - uses: revanite-io/osps-baseline-action@v1\n"),
			},
			wantResult: gemara.Failed,
			wantMsg:    "Scanner runs in caller.yml (job b calls called.yml, where job s step #2 uses revanite-io/osps-baseline-action@v1). FAIL recurring trigger: no schedule, push, or release in caller.yml (pull_request_target, workflow_dispatch). FAIL actions pinned to full commit SHAs: caller.yml: called.yml: actions/checkout@v5; caller.yml: called.yml: revanite-io/osps-baseline-action@v1. FAIL no pull_request_target: caller.yml",
		},
		{
			name:       "ACC: scanner container image in a run step, digest-pinned",
			files:      []data.WorkflowFile{wf("a.yml", "on:\n  schedule:\n    - cron: '0 0 * * 1'\njobs:\n  baseline:\n    steps:\n      - name: Evaluate\n        run: docker run ghcr.io/ossf/pvtr-github-repo-scanner:v0.31.0@sha256:cd5e\n")},
			wantResult: gemara.Passed,
			wantMsg:    "Scanner runs in a.yml (job baseline step Evaluate runs the scanner). PASS recurring trigger: a.yml on schedule. PASS actions pinned to full commit SHAs. PASS no pull_request_target",
		},
		{
			name:       "pvtr CLI and an unpinned docker action",
			files:      []data.WorkflowFile{wf("a.yml", "on: release\njobs:\n  s:\n    steps:\n      - uses: docker://alpine:3\n      - run: pvtr run -c config.yml\n")},
			wantResult: gemara.Failed,
			wantMsg:    "Scanner runs in a.yml (job s step #2 runs the scanner). PASS recurring trigger: a.yml on release. FAIL actions pinned to full commit SHAs: a.yml: docker://alpine:3. PASS no pull_request_target",
		},
		{
			name:       "remote reusable workflow that runs the scanner",
			files:      []data.WorkflowFile{wf("a.yml", "on: push\njobs:\n  scan:\n    uses: org/shared/.github/workflows/baseline.yml@"+sha+"\n")},
			remote:     map[string]string{"https://github.com/org/shared/blob/" + sha + "/.github/workflows/baseline.yml": "on: workflow_call\njobs:\n  s:\n    steps:\n      - run: privateer run\n"},
			wantResult: gemara.Passed,
			wantMsg:    "Scanner runs in a.yml (job scan calls org/shared/.github/workflows/baseline.yml@" + sha + ", where job s step #1 runs the scanner). PASS recurring trigger: a.yml on push. PASS actions pinned to full commit SHAs. PASS no pull_request_target",
		},
		{
			name:       "ad hoc results location warns even when the workflow passes",
			payload:    adhoc,
			files:      []data.WorkflowFile{wf("a.yml", "on: push"+actionJob)},
			wantResult: gemara.NeedsReview,
			wantMsg:    "Scanner runs in a.yml (job scan step Scan uses revanite-io/osps-baseline-action@" + sha + "). PASS recurring trigger: a.yml on push. PASS actions pinned to full commit SHAs. PASS no pull_request_target. WARN Security Insights lists a single ad hoc run as the scanner's results location instead of the recurring workflow: Privateer (adhoc result https://github.com/o/r/actions/runs/1)",
		},
		{
			name: "ACC: ad hoc run listed beside the recurring workflow warns but passes",
			payload: payloadWithTools(si.SecurityTool{Name: "OSPS Baseline Scanner (Privateer)", Results: si.SecurityToolResults{
				Adhoc: &si.Attestation{Location: "https://github.com/o/r/actions/runs/38016769353"},
				CI:    &si.Attestation{Location: "https://github.com/o/r/actions/workflows/osps-baseline.yml"},
			}}),
			files:      []data.WorkflowFile{wf("a.yml", "on: push"+actionJob)},
			wantResult: gemara.Passed,
			wantMsg:    "Scanner runs in a.yml (job scan step Scan uses revanite-io/osps-baseline-action@" + sha + "). PASS recurring trigger: a.yml on push. PASS actions pinned to full commit SHAs. PASS no pull_request_target. WARN Security Insights also lists a single one-off run as a scanner results location: OSPS Baseline Scanner (Privateer) (https://github.com/o/r/actions/runs/38016769353)",
		},
		{
			name:       "no scanner workflow",
			files:      []data.WorkflowFile{unrelated},
			wantResult: gemara.Failed,
			wantMsg:    "No workflow on the default branch runs the OSPS Baseline scanner (osps-baseline-action, pvtr-publish-results, the pvtr-github-repo-scanner action or image, or the privateer/pvtr CLI)",
		},
		{
			name:       "unparseable workflow and no scanner",
			files:      []data.WorkflowFile{wf("bad.yml", "on: [push\njobs: {")},
			wantResult: gemara.NeedsReview,
			wantMsg:    "No OSPS Baseline scanner workflow found, but these workflows could not be parsed: bad.yml",
		},
		{
			name:       "workflows unreadable",
			err:        errors.New("boom"),
			wantResult: gemara.NeedsReview,
			wantMsg:    "Could not read workflows on the default branch: boom",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubWorkflows(t, tt.files, tt.err)
			orig := fetchURL
			fetchURL = func(_ *data.Payload, u string) (data.FetchedURL, error) {
				if body, ok := tt.remote[u]; ok {
					return data.FetchedURL{StatusCode: 200, Body: []byte(body)}, nil
				}
				return data.FetchedURL{StatusCode: 404}, nil
			}
			t.Cleanup(func() { fetchURL = orig })
			result, msg, _ := ScannerWorkflowRequirements(tt.payload)
			if result != tt.wantResult || msg != tt.wantMsg {
				t.Errorf("got (%v, %q)\nwant (%v, %q)", result, msg, tt.wantResult, tt.wantMsg)
			}
		})
	}
}
