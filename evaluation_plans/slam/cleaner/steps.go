package cleaner

import (
	_ "embed"
	"fmt"
	"path"
	"slices"
	"strings"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cueerrors "cuelang.org/go/cue/errors"
	cueyaml "cuelang.org/go/encoding/yaml"
	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/gemaraproj/go-gemara"
	"github.com/goccy/go-yaml"
	"github.com/ossf/si-tooling/v2/si"
)

// insightsNames are the file names si-tooling's discovery accepts, as
// si.Discover lists them (unexported there): the spec's two, then legacy
// spellings it still finds.
var insightsNames = append(si.SecurityInsightsFilenames(), "SECURITY-INSIGHTS.yml", "SECURITY_INSIGHTS.yml", "security_insights.yml")

// SecurityInsightsFileFound takes the file si-tooling discovers, at the root
// or in .github/, under any name it accepts. Two Security Insights files in
// one location are an error, because readers may pick different ones.
func SecurityInsightsFileFound(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	for _, location := range []struct {
		dir     string
		entries []string
	}{{"the repository root", payload.RootEntries}, {".github/", payload.GitHubDirEntries}} {
		var found []string
		for _, entry := range location.entries {
			if slices.Contains(insightsNames, entry) {
				found = append(found, entry)
			}
		}
		if len(found) > 1 {
			return gemara.Failed, fmt.Sprintf("Found %d Security Insights files in %s (%s); keep only one", len(found), location.dir, strings.Join(found, ", ")), gemara.High
		}
	}
	if payload.InsightsPath == "" {
		return gemara.Failed, "si-tooling found no Security Insights file (security-insights.yml or security-insights.yaml, at the root or in .github/)", gemara.High
	}
	message = "si-tooling found the Security Insights file at " + payload.InsightsPath
	if !slices.Contains(si.SecurityInsightsFilenames(), path.Base(payload.InsightsPath)) {
		message += "; the spec names security-insights.yml or .yaml, and si-tooling accepts this name as a legacy spelling"
	}
	return gemara.Passed, message, gemara.High
}

func ValidatesWithSITooling(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if payload.InsightsError != nil {
		return gemara.Failed, fmt.Sprintf("Security Insights file does not validate with si-tooling: %s", payload.InsightsError), gemara.High
	}
	if payload.InsightsPath == "" {
		return gemara.Failed, "si-tooling found no Security Insights file at the repository root or in .github/", gemara.High
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

// RepositoryURLMatches requires repository.url to name the repository under
// review, so a file copied from another project does not pass as this one's.
func RepositoryURLMatches(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	want := fmt.Sprintf("https://github.com/%s/%s", payload.Owner, payload.Repo)
	var got string
	if payload.Insights.Repository != nil {
		got = strings.TrimSuffix(strings.TrimSuffix(strings.TrimSpace(string(payload.Insights.Repository.Url)), "/"), ".git")
	}
	if !strings.EqualFold(got, want) {
		return gemara.Failed, fmt.Sprintf("Security Insights repository.url is %q, not the reviewed repository %s", got, want), gemara.High
	}
	return gemara.Passed, "Security Insights file has every required field, validates against the v" + schemaVersion + " CUE schema, and describes " + want, gemara.High
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

// schemaCUE is spec/schema.cue from github.com/ossf/security-insights at
// v2.2.0, the current release.
//
//go:embed schema/security-insights-v2.2.0.cue
var schemaCUE []byte

const schemaVersion = "2.2.0"

// maxSchemaErrors keeps the message readable for a badly broken file.
const maxSchemaErrors = 10

// ValidatesAgainstSchema runs the file through the specification's own CUE
// schema, which si-tooling does not: si-tooling only decodes the YAML strictly,
// so wrong enum values, malformed URLs, emails, and dates pass it.
func ValidatesAgainstSchema(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if len(payload.InsightsRaw) == 0 {
		return gemara.Failed, "No Security Insights file content to check", gemara.High
	}
	problems, err := schemaProblems(payload.InsightsRaw)
	if err != nil {
		return gemara.NeedsReview, "Could not run the Security Insights CUE schema: " + err.Error(), gemara.Low
	}
	if len(problems) > 0 {
		if len(problems) > maxSchemaErrors {
			problems = append(problems[:maxSchemaErrors], fmt.Sprintf("and %d more", len(problems)-maxSchemaErrors))
		}
		return gemara.Failed, fmt.Sprintf("Security Insights file does not validate against the v%s CUE schema: %s", schemaVersion, strings.Join(problems, "; ")), gemara.High
	}
	return gemara.Passed, fmt.Sprintf("Security Insights file has every required field and validates against the v%s CUE schema", schemaVersion), gemara.High
}

// schemaProblems unifies the file with #SecurityInsights and lists every
// violation; err is a fault in the schema or the YAML, not the file's content.
func schemaProblems(raw []byte) ([]string, error) {
	ctx := cuecontext.New()
	schema := ctx.CompileBytes(schemaCUE)
	if schema.Err() != nil {
		return nil, schema.Err()
	}
	file, err := cueyaml.Extract("security-insights.yml", raw)
	if err != nil {
		return nil, err
	}
	value := schema.LookupPath(cue.ParsePath("#SecurityInsights")).Unify(ctx.BuildFile(file))
	var problems []string
	for _, e := range cueerrors.Errors(value.Validate(cue.Concrete(true))) {
		problems = append(problems, strings.TrimPrefix(e.Error(), "#SecurityInsights."))
	}
	slices.Sort(problems)
	return slices.Compact(problems), nil
}
