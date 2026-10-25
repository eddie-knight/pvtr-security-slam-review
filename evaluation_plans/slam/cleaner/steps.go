package cleaner

import (
	"fmt"
	"slices"
	"strings"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/gemaraproj/go-gemara"
	"github.com/goccy/go-yaml"
	"github.com/ossf/si-tooling/v2/si"
)

const requiredFileName = "security-insights.yml"

func FileNamedSecurityInsightsYml(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if slices.Contains(payload.RootEntries, requiredFileName) {
		return gemara.Passed, "Security Insights file is named " + requiredFileName, gemara.High
	}
	for _, entry := range payload.RootEntries {
		for _, name := range si.SecurityInsightsFilenames() {
			if strings.EqualFold(entry, name) {
				return gemara.Failed, fmt.Sprintf("Security Insights file is named %s; the badge requires the lowercase name %s", entry, requiredFileName), gemara.High
			}
		}
	}
	return gemara.Failed, "No " + requiredFileName + " found at the repository root", gemara.High
}

func ValidatesWithSITooling(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.InsightsError != nil {
		return gemara.Failed, fmt.Sprintf("Security Insights file does not validate with si-tooling: %s", payload.InsightsError), gemara.High
	}
	if payload.InsightsPath == "" {
		return gemara.Failed, "No Security Insights file found at the repository root", gemara.High
	}
	return gemara.Passed, "Security Insights file validates with si-tooling: " + payload.InsightsPath, gemara.High
}

// requiredFields are the fields Security Insights spec/schema.cue v2.2.0 marks
// required (v2.1.0 is identical; v2.0.0 also allows the [+] lists to be empty).
// "x?" skips the rest of the path when x is absent, "x[]" checks each item of
// an optional list, and "x[+]" requires at least one item.
var requiredFields = []string{
	"header.schema-version",
	"header.last-updated",
	"header.last-reviewed",
	"header.url",

	"project?.name",
	"project?.steward?.uri",
	"project?.steward?.comment",
	"project?.administrators[+].name",
	"project?.administrators[+].primary",
	"project?.repositories[+].name",
	"project?.repositories[+].comment",
	"project?.repositories[+].url",
	"project?.vulnerability-reporting.reports-accepted",
	"project?.vulnerability-reporting.bug-bounty-available",
	"project?.vulnerability-reporting.contact?.name",
	"project?.vulnerability-reporting.contact?.primary",

	"repository.status",
	"repository.url",
	"repository.accepts-change-request",
	"repository.accepts-automated-change-request",
	"repository.core-team[+].name",
	"repository.core-team[+].primary",
	"repository.license.url",
	"repository.license.expression",
	"repository.security.assessments.self.comment",
	"repository.security.assessments.third-party[].comment",
	"repository.security.champions[].name",
	"repository.security.champions[].primary",
	"repository.security.tools[].name",
	"repository.security.tools[].type",
	"repository.security.tools[].rulesets",
	"repository.security.tools[].integration.adhoc",
	"repository.security.tools[].integration.ci",
	"repository.security.tools[].integration.release",
	"repository.security.tools[].results",
	"repository.security.tools[].results.adhoc?.name",
	"repository.security.tools[].results.adhoc?.location",
	"repository.security.tools[].results.adhoc?.predicate-uri",
	"repository.security.tools[].results.ci?.name",
	"repository.security.tools[].results.ci?.location",
	"repository.security.tools[].results.ci?.predicate-uri",
	"repository.security.tools[].results.release?.name",
	"repository.security.tools[].results.release?.location",
	"repository.security.tools[].results.release?.predicate-uri",
	"repository.release?.automated-pipeline",
	"repository.release?.distribution-points[+].uri",
	"repository.release?.distribution-points[+].comment",
	"repository.release?.license?.url",
	"repository.release?.license?.expression",
	"repository.release?.attestations[].name",
	"repository.release?.attestations[].location",
	"repository.release?.attestations[].predicate-uri",
}

// RequiredFieldsPresent reads the raw YAML because the parsed struct cannot
// tell an absent boolean from false.
func RequiredFieldsPresent(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.InsightsRaw) == 0 {
		return gemara.Failed, "No Security Insights file content to check", gemara.High
	}
	var doc map[string]any
	if err := yaml.Unmarshal(payload.InsightsRaw, &doc); err != nil {
		return gemara.Failed, fmt.Sprintf("Security Insights file is not valid YAML: %s", err), gemara.High
	}
	missing := missingFields(doc)
	if len(missing) > 0 {
		return gemara.Failed, fmt.Sprintf("Security Insights file is missing required fields: %s", strings.Join(missing, ", ")), gemara.High
	}
	return gemara.Passed, "Security Insights file has every required field", gemara.High
}

func missingFields(doc map[string]any) []string {
	var missing []string
	// The schema leaves project optional so a file can inherit it from a parent
	header, _ := doc["header"].(map[string]any)
	if doc["project"] == nil && header["project-si-source"] == nil {
		missing = append(missing, "project")
	}
	seen := map[string]bool{}
	for _, path := range requiredFields {
		for _, m := range check(doc, "", strings.Split(path, ".")) {
			if !seen[m] {
				seen[m] = true
				missing = append(missing, m)
			}
		}
	}
	return missing
}

// check walks segments under node and returns the dotted paths that are
// missing. A parent that is missing is reported once, not per child.
func check(node any, prefix string, segments []string) []string {
	seg := segments[0]
	name := strings.TrimRight(seg, "?[]+")
	path := strings.TrimPrefix(prefix+"."+name, ".")
	obj, _ := node.(map[string]any)
	value := obj[name]
	if value == nil {
		if strings.HasSuffix(seg, "?") || strings.HasSuffix(seg, "[]") {
			return nil
		}
		return []string{path}
	}
	rest := segments[1:]
	if strings.HasSuffix(seg, "]") {
		items, _ := value.([]any)
		if len(items) == 0 && strings.HasSuffix(seg, "[+]") {
			return []string{path}
		}
		var missing []string
		for i, item := range items {
			missing = append(missing, check(item, fmt.Sprintf("%s[%d]", path, i), rest)...)
		}
		return missing
	}
	if len(rest) == 0 {
		return nil
	}
	return check(value, path, rest)
}
