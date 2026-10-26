package defender

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/reusable_steps"
	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
)

const (
	// Two runs at different times are the least that shows a schedule rather
	// than a one-off publish.
	minRecurringRuns = 2
	// The publish workflow runs on every default-branch push; a result older
	// than a month is no longer a live scan.
	maxResultAge = 30 * 24 * time.Hour
	// recentEvaluations is how far back the recurrence check looks.
	recentEvaluations = 20
	// trustedWorkflowPrefix is the reusable workflow grc.store trusts to sign
	// published results.
	trustedWorkflowPrefix = "revanite-io/pvtr-publish-results/"
	baselineCatalogPrefix = "osps-baseline"

	maxEvidenceDocuments     = 16
	maxEvidenceDocumentBytes = 16 * 1024
)

var (
	getGrcStoreTarget      = (*data.Payload).GetGrcStoreTarget
	getGrcStoreEvaluations = (*data.Payload).GetGrcStoreEvaluations
	getGrcStoreLog         = (*data.Payload).GetGrcStoreLog
	fetchURL               = (*data.Payload).FetchURL
	now                    = time.Now
)

// GrcStoreTargetDeclared requires a Security Insights tool whose results
// location is a grc.store target page: the Defender is judged from there.
func GrcStoreTargetDeclared(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	namespace, id, ok := declaredTarget(payload)
	if !ok {
		return gemara.Failed, "No grc.store target page found in repository.security.tools results; the Defender badge requires the grc.store publish workflow, so list its target page (https://grc.store/targets/<namespace>/<target>) under repository.security.tools", gemara.High
	}
	return gemara.Passed, fmt.Sprintf("Security Insights declares grc.store target %s/%s", namespace, id), gemara.High
}

// ResultPublished requires the declared target to exist on grc.store with an
// OSPS Baseline evaluation published against it.
func ResultPublished(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	target, namespace, id, result, message := loadTarget(payload)
	if target == nil {
		return result, message, gemara.High
	}
	latest, ok := latestBaselineEvaluation(target)
	if !ok {
		return gemara.Failed, fmt.Sprintf("grc.store target %s/%s has no published OSPS Baseline evaluation", namespace, id), gemara.High
	}
	return gemara.Passed, fmt.Sprintf("grc.store target %s/%s has a published OSPS Baseline evaluation (%s, run %s)", namespace, id, latest.LogVersion, latest.RunAt), gemara.High
}

// ResultIsRecurring requires more than one published run, the newest recent
// enough to count as a live scan.
func ResultIsRecurring(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	namespace, id, ok := declaredTarget(payload)
	if !ok {
		return gemara.Failed, "No grc.store target page found in repository.security.tools results", gemara.High
	}
	evaluations, err := getGrcStoreEvaluations(&payload, namespace, id, recentEvaluations)
	if err != nil {
		return gemara.NeedsReview, fmt.Sprintf("Could not read grc.store evaluations for %s/%s: %s", namespace, id, err), gemara.Low
	}
	runs := map[time.Time]bool{}
	var newest time.Time
	for _, evaluation := range evaluations {
		runAt, err := time.Parse(time.RFC3339, evaluation.RunAt)
		if err != nil || !isBaseline(evaluation) {
			continue
		}
		runs[runAt] = true
		if runAt.After(newest) {
			newest = runAt
		}
	}
	if len(runs) < minRecurringRuns {
		return gemara.Failed, fmt.Sprintf("grc.store target %s/%s has %d published OSPS Baseline run(s); a recurring scan needs at least %d", namespace, id, len(runs), minRecurringRuns), gemara.High
	}
	if age := now().Sub(newest); age > maxResultAge {
		return gemara.Failed, fmt.Sprintf("The newest OSPS Baseline result for %s/%s was published %s, more than %d days ago; the scan is not running", namespace, id, newest.Format(time.DateOnly), int(maxResultAge.Hours()/24)), gemara.High
	}
	return gemara.Passed, fmt.Sprintf("grc.store target %s/%s has %d recent OSPS Baseline runs, the newest on %s", namespace, id, len(runs), newest.Format(time.DateOnly)), gemara.High
}

// TrustedPublisher requires the target to be bound to this repository by
// GitHub OIDC and the latest result to be signed by the publish workflow
// running in this repository.
func TrustedPublisher(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	target, namespace, id, result, message := loadTarget(payload)
	if target == nil {
		return result, message, gemara.High
	}
	repository := payload.Owner + "/" + payload.Repo
	if target.VerificationMethod != "github-oidc" || target.VerifiedAt == "" {
		return gemara.Failed, fmt.Sprintf("grc.store target %s/%s is not verified by GitHub OIDC (verification method %q); register this repository as its trusted publisher", namespace, id, target.VerificationMethod), gemara.High
	}
	if !strings.EqualFold(strings.TrimSuffix(target.URI, "/"), "https://github.com/"+repository) {
		return gemara.Failed, fmt.Sprintf("grc.store target %s/%s is bound to %s, not https://github.com/%s", namespace, id, target.URI, repository), gemara.High
	}
	latest, ok := latestBaselineEvaluation(target)
	if !ok {
		return gemara.Failed, fmt.Sprintf("grc.store target %s/%s has no published OSPS Baseline evaluation", namespace, id), gemara.High
	}
	if !strings.EqualFold(latest.Signer.CallerRepository, repository) {
		return gemara.Failed, fmt.Sprintf("The latest result for %s/%s was published from %q, not %s", namespace, id, latest.Signer.CallerRepository, repository), gemara.High
	}
	if !strings.HasPrefix(latest.Signer.WorkflowRef, trustedWorkflowPrefix) {
		return gemara.Failed, fmt.Sprintf("The latest result for %s/%s was signed by workflow %q, not the %s publish workflow", namespace, id, latest.Signer.WorkflowRef, strings.TrimSuffix(trustedWorkflowPrefix, "/")), gemara.High
	}
	return gemara.Passed, fmt.Sprintf("grc.store target %s/%s is verified by GitHub OIDC and its latest result was signed by %s from %s", namespace, id, latest.Signer.WorkflowRef, repository), gemara.High
}

// LatestResultHasNoFailures requires every control of the newest published
// OSPS Baseline result that applies at the project's maturity level to have
// been evaluated without a failure.
func LatestResultHasNoFailures(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	level, ok := maturityLevel(payload)
	if !ok {
		return gemara.NeedsReview, maturityLevelMissing, gemara.Low
	}
	target, namespace, id, result, message := loadTarget(payload)
	if target == nil {
		return result, message, gemara.High
	}
	latest, ok := latestBaselineEvaluation(target)
	if !ok {
		return gemara.Failed, fmt.Sprintf("grc.store target %s/%s has no published OSPS Baseline evaluation", namespace, id), gemara.High
	}
	entries, err := loadLog(payload, latest)
	if err != nil {
		return gemara.NeedsReview, fmt.Sprintf("Could not read the latest published log for %s/%s: %s; manual review needed", namespace, id, err), gemara.Low
	}
	var failed, skipped []string
	for _, entry := range entries {
		if !appliesAt(entry, level) {
			continue
		}
		switch {
		case entry.Result == gemara.Failed.String() || entry.Result == gemara.Unknown.String():
			failed = append(failed, entry.Requirement.EntryID)
		case entry.Result == gemara.NotRun.String() && entry.StepsExecuted == 0:
			skipped = append(skipped, entry.Requirement.EntryID)
		}
	}
	if len(failed) > 0 {
		return gemara.Failed, fmt.Sprintf("The latest OSPS Baseline result for %s/%s (%s) reports %d failed or unknown control(s) at maturity level %d: %s", namespace, id, latest.LogVersion, len(failed), level, strings.Join(failed, ", ")), gemara.High
	}
	if len(skipped) > 0 {
		return gemara.Failed, fmt.Sprintf("The latest OSPS Baseline result for %s/%s (%s) did not evaluate %d control(s) that apply at maturity level %d (%s); publish a scan at maturity level %d", namespace, id, latest.LogVersion, len(skipped), level, strings.Join(skipped, ", "), level), gemara.High
	}
	return gemara.Passed, fmt.Sprintf("The latest OSPS Baseline result for %s/%s (%s) reports no failed controls at maturity level %d", namespace, id, latest.LogVersion, level), gemara.High
}

// AIReviewUncheckedControlEvidence asks the model whether the documentation
// linked from Security Insights covers the controls at the project's maturity
// level that the latest published result could not check (Needs Review and
// Not Run).
func AIReviewUncheckedControlEvidence(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	level, ok := maturityLevel(payload)
	if !ok {
		return gemara.NeedsReview, maturityLevelMissing, gemara.Low
	}
	target, namespace, id, result, message := loadTarget(payload)
	if target == nil {
		return result, message, gemara.High
	}
	latest, ok := latestBaselineEvaluation(target)
	if !ok {
		return gemara.Failed, fmt.Sprintf("grc.store target %s/%s has no published OSPS Baseline evaluation", namespace, id), gemara.High
	}
	entries, err := loadLog(payload, latest)
	if err != nil {
		return gemara.NeedsReview, fmt.Sprintf("Could not read the latest published log for %s/%s: %s; manual review needed", namespace, id, err), gemara.Low
	}
	var unchecked []uncheckedControl
	for _, entry := range entries {
		if !appliesAt(entry, level) || (entry.Result != gemara.NeedsReview.String() && entry.Result != gemara.NotRun.String()) {
			continue
		}
		unchecked = append(unchecked, uncheckedControl{
			ID:             entry.Requirement.EntryID,
			Result:         entry.Result,
			Applicability:  entry.Applicability,
			Message:        entry.Message,
			Recommendation: entry.Recommendation,
		})
	}
	if len(unchecked) == 0 {
		return gemara.Passed, fmt.Sprintf("The latest OSPS Baseline result for %s/%s (%s) has no Needs Review or Not Run controls at maturity level %d", namespace, id, latest.LogVersion, level), gemara.High
	}

	targetPage := fmt.Sprintf("https://grc.store/targets/%s/%s", namespace, id)
	packet := uncheckedControlEvidence{
		PublishedResult: publishedResult{
			TargetPage: targetPage,
			LogVersion: latest.LogVersion,
			RunAt:      latest.RunAt,
			Catalog:    latest.CatalogID,
			Counts:     latest.Counts,
		},
		MaturityLevel:     level,
		UncheckedControls: unchecked,
		Collection:        evidenceCollection{Complete: true, Scope: evidenceCollectionScope},
	}
	sources := []string{targetPage}
	for i, link := range documentationLinks(payload.Insights) {
		if i == maxEvidenceDocuments {
			packet.Collection.Complete = false
			packet.Collection.Unretrieved = append(packet.Collection.Unretrieved, link.URL+" (document limit reached)")
			continue
		}
		document := evidenceDocument{Field: link.Field, URL: link.URL}
		fetched, err := fetchURL(&payload, link.URL)
		switch {
		case err != nil:
			document.Error = err.Error()
		case fetched.StatusCode < 200 || fetched.StatusCode > 299:
			document.Error = fmt.Sprintf("HTTP %d", fetched.StatusCode)
		default:
			document.Content, document.Truncated = documentText(fetched)
			sources = append(sources, link.URL)
		}
		if document.Error != "" {
			packet.Collection.Complete = false
			packet.Collection.Unretrieved = append(packet.Collection.Unretrieved, link.URL+": "+document.Error)
		}
		packet.Documentation = append(packet.Documentation, document)
	}
	material, err := json.Marshal(packet)
	if err != nil {
		return gemara.NeedsReview, "Could not assemble evidence for AI review: " + err.Error(), gemara.Low
	}
	return reusable_steps.AIReview(payload, "defender-unchecked-control-evidence", string(material), sources)
}

const evidenceCollectionScope = "The unchecked controls are every Needs Review and Not Run entry in the latest evaluation log published to grc.store whose applicability includes the project's maturity level, which the reviewer supplied as maturity_level. Documentation is the documentation, vulnerability policy and assessment evidence URLs declared in Security Insights, each fetched once with HTML reduced to text and content capped; links inside those documents were not followed. Complete means every declared URL was retrieved, not that the project's documentation is exhaustive."

type uncheckedControlEvidence struct {
	PublishedResult   publishedResult    `json:"published_result"`
	MaturityLevel     int                `json:"maturity_level"`
	UncheckedControls []uncheckedControl `json:"unchecked_controls"`
	Documentation     []evidenceDocument `json:"documentation"`
	Collection        evidenceCollection `json:"collection"`
}

type publishedResult struct {
	TargetPage string `json:"target_page"`
	LogVersion string `json:"log_version"`
	RunAt      string `json:"run_at"`
	Catalog    string `json:"catalog"`
	Counts     any    `json:"counts"`
}

type uncheckedControl struct {
	ID             string   `json:"id"`
	Result         string   `json:"result"`
	Applicability  []string `json:"applicability"`
	Message        string   `json:"message,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
}

type evidenceDocument struct {
	Field     string `json:"security_insights_field"`
	URL       string `json:"url"`
	Content   string `json:"content,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Error     string `json:"error,omitempty"`
}

type evidenceCollection struct {
	Complete    bool     `json:"complete"`
	Scope       string   `json:"scope"`
	Unretrieved []string `json:"unretrieved,omitempty"`
}

// assessmentLogEntry is the slice of a published Gemara assessment log the
// Defender steps read.
type assessmentLogEntry struct {
	Requirement struct {
		EntryID string `json:"entry-id"`
	} `json:"requirement"`
	Result         string   `json:"result"`
	Message        string   `json:"message"`
	Recommendation string   `json:"recommendation"`
	Applicability  []string `json:"applicability"`
	StepsExecuted  int      `json:"steps-executed"`
}

func loadLog(payload data.Payload, evaluation data.GrcStoreEvaluation) ([]assessmentLogEntry, error) {
	raw, err := getGrcStoreLog(&payload, evaluation.LogNamespace, evaluation.LogID, evaluation.LogVersion)
	if err != nil {
		return nil, err
	}
	var log struct {
		Evaluations []struct {
			AssessmentLogs []assessmentLogEntry `json:"assessment-logs"`
		} `json:"evaluations"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		return nil, fmt.Errorf("failed to decode evaluation log %s/%s@%s: %w", evaluation.LogNamespace, evaluation.LogID, evaluation.LogVersion, err)
	}
	var entries []assessmentLogEntry
	for _, evaluation := range log.Evaluations {
		entries = append(entries, evaluation.AssessmentLogs...)
	}
	return entries, nil
}

const maturityLevelMissing = "Set the maturity_level var (1-3) to the project's OSPS Baseline maturity level"

// maturityLevel reads the maturity_level var as an int or a numeric string.
func maturityLevel(payload data.Payload) (int, bool) {
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

// appliesAt reports whether a log entry belongs to the level. The catalog
// lists every level a control applies at, so a Level 1 control lists all three.
func appliesAt(entry assessmentLogEntry, level int) bool {
	return slices.Contains(entry.Applicability, fmt.Sprintf("maturity-%d", level))
}

// declaredTarget finds the first Security Insights tool result location of
// the form https://grc.store/targets/{namespace}/{id}.
func declaredTarget(payload data.Payload) (namespace, id string, ok bool) {
	for _, tool := range payload.Insights.Repository.SecurityPosture.Tools {
		for _, attestation := range []*si.Attestation{tool.Results.CI, tool.Results.Release, tool.Results.Adhoc} {
			if attestation == nil {
				continue
			}
			if namespace, id, ok = parseTargetPage(string(attestation.Location)); ok {
				return namespace, id, true
			}
		}
	}
	return "", "", false
}

func parseTargetPage(location string) (namespace, id string, ok bool) {
	u, err := url.Parse(strings.TrimSpace(location))
	if err != nil || u.Scheme != "https" || !strings.EqualFold(u.Host, "grc.store") {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 3 || parts[0] != "targets" || parts[1] == "" || parts[2] == "" {
		return "", "", false
	}
	return parts[1], parts[2], true
}

// loadTarget fetches the declared target. A nil target comes with the
// result and message the calling step should return.
func loadTarget(payload data.Payload) (target *data.GrcStoreTarget, namespace, id string, result gemara.Result, message string) {
	namespace, id, ok := declaredTarget(payload)
	if !ok {
		return nil, "", "", gemara.Failed, "No grc.store target page found in repository.security.tools results"
	}
	target, err := getGrcStoreTarget(&payload, namespace, id)
	if err != nil {
		return nil, namespace, id, gemara.NeedsReview, fmt.Sprintf("Could not read grc.store target %s/%s: %s", namespace, id, err)
	}
	if target == nil {
		return nil, namespace, id, gemara.Failed, fmt.Sprintf("grc.store has no target %s/%s; create it and publish results with the pvtr-publish-results workflow", namespace, id)
	}
	return target, namespace, id, gemara.Passed, ""
}

// latestBaselineEvaluation is the newest OSPS Baseline evaluation across all
// of the target's versions.
func latestBaselineEvaluation(target *data.GrcStoreTarget) (latest data.GrcStoreEvaluation, ok bool) {
	var newest time.Time
	for _, version := range target.Versions {
		evaluation := version.Latest
		runAt, err := time.Parse(time.RFC3339, evaluation.RunAt)
		if err != nil || !isBaseline(evaluation) {
			continue
		}
		if !ok || runAt.After(newest) {
			latest, newest, ok = evaluation, runAt, true
		}
	}
	return latest, ok
}

func isBaseline(evaluation data.GrcStoreEvaluation) bool {
	return strings.HasPrefix(evaluation.CatalogID, baselineCatalogPrefix)
}

type documentationLink struct {
	Field string
	URL   string
}

// documentationLinks lists the Security Insights URLs where a project writes
// down how it meets controls, in a fixed order, without duplicates.
func documentationLinks(insights si.SecurityInsights) []documentationLink {
	repoDocs, projectDocs := insights.Repository.Documentation, insights.Project.Documentation
	candidates := []struct {
		field string
		url   *si.URL
	}{
		{"repository.documentation.security-policy", repoDocs.SecurityPolicy},
		{"project.vulnerability-reporting.policy", insights.Project.VulnerabilityReporting.Policy},
		{"repository.documentation.contributing-guide", repoDocs.ContributingGuide},
		{"repository.documentation.review-policy", repoDocs.ReviewPolicy},
		{"repository.documentation.governance", repoDocs.Governance},
		{"repository.documentation.dependency-management-policy", repoDocs.DependencyManagementPolicy},
		{"project.documentation.design", projectDocs.Design},
		{"project.documentation.detailed-guide", projectDocs.DetailedGuide},
		{"project.documentation.quickstart-guide", projectDocs.QuickstartGuide},
		{"project.documentation.release-process", projectDocs.ReleaseProcess},
		{"project.documentation.support-policy", projectDocs.SupportPolicy},
		{"project.documentation.signature-verification", projectDocs.SignatureVerification},
		{"repository.security.assessments.self.evidence", insights.Repository.SecurityPosture.Assessments.Self.Evidence},
	}
	for i, assessment := range insights.Repository.SecurityPosture.Assessments.ThirdPartyAssessment {
		candidates = append(candidates, struct {
			field string
			url   *si.URL
		}{fmt.Sprintf("repository.security.assessments.third-party[%d].evidence", i), assessment.Evidence})
	}
	var links []documentationLink
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if candidate.url == nil {
			continue
		}
		link := strings.TrimSpace(string(*candidate.url))
		if link == "" || seen[link] {
			continue
		}
		seen[link] = true
		links = append(links, documentationLink{Field: candidate.field, URL: link})
	}
	return links
}

var (
	htmlNonText   = regexp.MustCompile(`(?is)<(script|style|noscript|svg)\b.*?</(script|style|noscript|svg)>|<!--.*?-->`)
	htmlTag       = regexp.MustCompile(`(?s)<[^>]*>`)
	blankRuns     = regexp.MustCompile(`[ \t\r\f\v]+`)
	blankLineRuns = regexp.MustCompile(`\s*\n\s*`)
)

// documentText returns the fetched body as text, HTML reduced to its visible
// words, capped at maxEvidenceDocumentBytes.
func documentText(fetched data.FetchedURL) (text string, truncated bool) {
	text = string(fetched.Body)
	if strings.Contains(strings.ToLower(fetched.ContentType), "html") {
		text = htmlTag.ReplaceAllString(htmlNonText.ReplaceAllString(text, " "), " ")
		text = html.UnescapeString(text)
		text = blankLineRuns.ReplaceAllString(blankRuns.ReplaceAllString(text, " "), "\n")
	}
	text = strings.TrimSpace(text)
	truncated = fetched.Truncated
	if len(text) > maxEvidenceDocumentBytes {
		text, truncated = strings.ToValidUTF8(text[:maxEvidenceDocumentBytes], ""), true
	}
	return text, truncated
}
