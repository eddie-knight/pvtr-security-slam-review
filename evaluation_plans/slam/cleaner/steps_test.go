package cleaner

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
)

func strimzi(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/strimzi-security-insights.yml")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// minimal is the smallest file that satisfies every required field.
const minimal = `
header:
  schema-version: 2.2.0
  last-updated: '2026-10-14'
  last-reviewed: '2026-10-14'
  url: https://example.com/security-insights.yml
project:
  name: Example
  administrators:
    - name: Ada
      primary: true
  repositories:
    - name: example
      comment: the only repository
      url: https://github.com/example/example
  vulnerability-reporting:
    reports-accepted: true
    bug-bounty-available: false
repository:
  url: https://github.com/example/example
  status: active
  accepts-change-request: true
  accepts-automated-change-request: false
  core-team:
    - name: Ada
      primary: true
  license:
    url: https://github.com/example/example/blob/main/LICENSE
    expression: Apache-2.0
  security:
    assessments:
      self:
        comment: none yet
`

func Test_FileNamedSecurityInsightsYml(t *testing.T) {
	tests := []struct {
		name       string
		entries    []string
		wantResult gemara.Result
		wantMsg    string
	}{
		{"exact name", []string{"README.md", "security-insights.yml"}, gemara.Passed, "Security Insights file is named security-insights.yml"},
		{"uppercase", []string{"SECURITY-INSIGHTS.yml"}, gemara.Failed, "Security Insights file is named SECURITY-INSIGHTS.yml; the badge requires the lowercase name security-insights.yml"},
		{"yaml extension", []string{"security-insights.yaml"}, gemara.Failed, "Security Insights file is named security-insights.yaml; the badge requires the lowercase name security-insights.yml"},
		{"missing", []string{"README.md"}, gemara.Failed, "No security-insights.yml found at the repository root"},
		// SOaC
		{"both extensions", []string{"security-insights.yml", "security-insights.yaml"}, gemara.Failed, "Found 2 Security Insights files at the repository root (security-insights.yml, security-insights.yaml); keep only security-insights.yml"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, msg, conf := FileNamedSecurityInsightsYml(data.Payload{RootEntries: tt.entries})
			if result != tt.wantResult || msg != tt.wantMsg || conf != gemara.High {
				t.Errorf("got (%v, %q, %v), want (%v, %q, High)", result, msg, conf, tt.wantResult, tt.wantMsg)
			}
		})
	}
}

func Test_ValidatesWithSITooling(t *testing.T) {
	tests := []struct {
		name       string
		payload    data.Payload
		wantResult gemara.Result
		wantMsg    string
	}{
		{"valid", data.Payload{InsightsPath: "security-insights.yml"}, gemara.Passed, "Security Insights file validates with si-tooling: security-insights.yml"},
		{"rejected", data.Payload{InsightsPath: "security-insights.yml", InsightsError: errors.New("unknown field \"foo\"")}, gemara.Failed, "Security Insights file does not validate with si-tooling: unknown field \"foo\""},
		{"no file", data.Payload{}, gemara.Failed, "No Security Insights file found at the repository root"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, msg, _ := ValidatesWithSITooling(tt.payload)
			if result != tt.wantResult || msg != tt.wantMsg {
				t.Errorf("got (%v, %q), want (%v, %q)", result, msg, tt.wantResult, tt.wantMsg)
			}
		})
	}
}

func Test_RequiredFieldsPresent(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantResult gemara.Result
		wantMsg    string
	}{
		{"minimal", minimal, gemara.Passed, "Security Insights file has every required field"},
		{
			name:       "missing booleans and list item fields are all reported",
			raw:        strings.NewReplacer("    bug-bounty-available: false\n", "", "      primary: true\n", "", "  accepts-change-request: true\n", "").Replace(minimal),
			wantResult: gemara.Failed,
			wantMsg:    "Security Insights file is missing required fields: project.administrators[0].primary, project.vulnerability-reporting.bug-bounty-available, repository.accepts-change-request, repository.core-team[0].primary",
		},
		{
			name:       "missing parent reported once",
			raw:        strings.Replace(minimal, "  license:\n    url: https://github.com/example/example/blob/main/LICENSE\n    expression: Apache-2.0\n", "", 1),
			wantResult: gemara.Failed,
			wantMsg:    "Security Insights file is missing required fields: repository.license",
		},
		{
			name:       "empty required list",
			raw:        strings.Replace(minimal, "  core-team:\n    - name: Ada\n      primary: true\n", "  core-team: []\n", 1),
			wantResult: gemara.Failed,
			wantMsg:    "Security Insights file is missing required fields: repository.core-team",
		},
		{
			name:       "optional section present but incomplete",
			raw:        minimal + "  release:\n    distribution-points:\n      - uri: https://example.com\n",
			wantResult: gemara.Failed,
			wantMsg:    "Security Insights file is missing required fields: repository.release.automated-pipeline, repository.release.distribution-points[0].comment",
		},
		{
			name:       "no project and no parent",
			raw:        minimal[:strings.Index(minimal, "project:")] + minimal[strings.Index(minimal, "repository:"):],
			wantResult: gemara.Failed,
			wantMsg:    "Security Insights file is missing required fields: project",
		},
		{
			name:       "project inherited from parent",
			raw:        strings.Replace(minimal[:strings.Index(minimal, "project:")]+minimal[strings.Index(minimal, "repository:"):], "header:\n", "header:\n  project-si-source: https://example.com/parent.yml\n", 1),
			wantResult: gemara.Passed,
			wantMsg:    "Security Insights file has every required field",
		},
		{"no content", "", gemara.Failed, "No Security Insights file content to check"},
		{"strimzi", string(strimzi(t)), gemara.Passed, "Security Insights file has every required field"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, msg, _ := RequiredFieldsPresent(data.Payload{InsightsRaw: []byte(tt.raw)})
			if result != tt.wantResult || msg != tt.wantMsg {
				t.Errorf("got (%v, %q), want (%v, %q)", result, msg, tt.wantResult, tt.wantMsg)
			}
		})
	}
}

func Test_ValidatesAgainstSchema(t *testing.T) {
	tests := []struct {
		name       string
		raw        string
		wantResult gemara.Result
		wantMsg    string
	}{
		{"minimal", minimal, gemara.Passed, "validates against the v2.2.0 CUE schema"},
		{"strimzi", string(strimzi(t)), gemara.Passed, "validates against the v2.2.0 CUE schema"},
		{"status outside the enum", strings.Replace(minimal, "status: active", "status: sort-of-active", 1), gemara.Failed, "repository.status"},
		{"malformed date", strings.Replace(minimal, "last-updated: '2026-10-14'", "last-updated: 'October 14'", 1), gemara.Failed, `header."last-updated": invalid value "October 14"`},
		{"plain-text url", strings.Replace(minimal, "url: https://example.com/security-insights.yml", "url: example.com/security-insights.yml", 1), gemara.Failed, "header.url"},
		{"unknown field", minimal + "  favourite-colour: blue\n", gemara.Failed, "favourite-colour"},
		{"no content", "", gemara.Failed, "No Security Insights file content to check"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, msg, _ := ValidatesAgainstSchema(data.Payload{InsightsRaw: []byte(tt.raw)})
			if result != tt.wantResult || !strings.Contains(msg, tt.wantMsg) {
				t.Errorf("got (%v, %q), want %v containing %q", result, msg, tt.wantResult, tt.wantMsg)
			}
		})
	}
}

func Test_RepositoryURLMatches(t *testing.T) {
	insights, err := si.Load([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	for owner, want := range map[string]gemara.Result{"example": gemara.Passed, "Example": gemara.Passed, "someone-else": gemara.Failed} {
		payload := data.Payload{Owner: owner, Repo: "example", Insights: *insights}
		if result, msg, _ := RepositoryURLMatches(payload); result != want {
			t.Errorf("owner %s: got %v (%s), want %v", owner, result, msg, want)
		}
	}
}

// Strimzi's real file should earn every Cleaner step.
func Test_StrimziPassesAllSteps(t *testing.T) {
	raw := strimzi(t)
	insights, err := si.Load(raw)
	if err != nil {
		t.Fatalf("si.Load: %v", err)
	}
	payload := data.Payload{
		Owner: "strimzi", Repo: "strimzi-kafka-operator",
		RootEntries:  []string{"README.md", "security-insights.yml"},
		Insights:     *insights,
		InsightsPath: "security-insights.yml",
		InsightsRaw:  raw,
	}
	for name, step := range map[string]func(data.Payload) (gemara.Result, string, gemara.ConfidenceLevel){
		"FileNamedSecurityInsightsYml": FileNamedSecurityInsightsYml,
		"ValidatesWithSITooling":       ValidatesWithSITooling,
		"RequiredFieldsPresent":        RequiredFieldsPresent,
		"ValidatesAgainstSchema":       ValidatesAgainstSchema,
		"RepositoryURLMatches":         RepositoryURLMatches,
	} {
		if result, msg, _ := step(payload); result != gemara.Passed {
			t.Errorf("%s: got %v (%s), want Passed", name, result, msg)
		}
	}
}
