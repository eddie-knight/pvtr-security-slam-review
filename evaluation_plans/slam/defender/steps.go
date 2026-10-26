package defender

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/reusable_steps"
	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
	"golang.org/x/mod/semver"
)

const (
	// Runs on two different days are the least that shows a schedule rather
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

// GrcStoreTargetDeclared requires the reviewer to name the project's grc.store
// target: the Defender is judged from there.
func GrcStoreTargetDeclared(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	namespace, id, ok := declaredTarget(payload)
	if !ok {
		return gemara.NeedsReview, grcStoreTargetMissing, gemara.Low
	}
	return gemara.Passed, fmt.Sprintf("Reviewing grc.store target %s/%s", namespace, id), gemara.High
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
	return gemara.Passed, fmt.Sprintf("grc.store target %s/%s has a published OSPS Baseline evaluation (%s, run %s)", namespace, id, resultLabel(latest), latest.RunAt), gemara.High
}

// ResultIsRecurring requires more than one published run, the newest recent
// enough to count as a live scan.
func ResultIsRecurring(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	namespace, id, ok := declaredTarget(payload)
	if !ok {
		return gemara.NeedsReview, grcStoreTargetMissing, gemara.Low
	}
	evaluations, err := getGrcStoreEvaluations(&payload, namespace, id, recentEvaluations)
	if err != nil {
		return gemara.NeedsReview, fmt.Sprintf("Could not read grc.store evaluations for %s/%s: %s", namespace, id, err), gemara.Low
	}
	// Only runs the trusted workflow published from this repository count.
	repository := payload.Owner + "/" + payload.Repo
	days := map[string]bool{}
	var newest time.Time
	for _, evaluation := range evaluations {
		runAt, err := time.Parse(time.RFC3339, evaluation.RunAt)
		if err != nil || !isBaseline(evaluation) || !trustedSigner(evaluation, repository) {
			continue
		}
		days[runAt.UTC().Format(time.DateOnly)] = true
		if runAt.After(newest) {
			newest = runAt
		}
	}
	if len(days) < minRecurringRuns {
		return gemara.Failed, fmt.Sprintf("grc.store target %s/%s has OSPS Baseline runs published by %s from %s on %d day(s); a recurring scan needs runs on at least %d different days", namespace, id, strings.TrimSuffix(trustedWorkflowPrefix, "/"), repository, len(days), minRecurringRuns), gemara.High
	}
	if age := now().Sub(newest); age > maxResultAge {
		return gemara.Failed, fmt.Sprintf("The newest OSPS Baseline result for %s/%s was published %s, more than %d days ago; the scan is not running", namespace, id, newest.Format(time.DateOnly), int(maxResultAge.Hours()/24)), gemara.High
	}
	return gemara.Passed, fmt.Sprintf("grc.store target %s/%s has trusted OSPS Baseline runs on %d different days, the newest on %s", namespace, id, len(days), newest.Format(time.DateOnly)), gemara.High
}

// trustedSigner reports whether the publish workflow signed the run from the
// repository. grc.store verified the signature; this only reads its record.
func trustedSigner(evaluation data.GrcStoreEvaluation, repository string) bool {
	return strings.EqualFold(evaluation.Signer.CallerRepository, repository) && strings.HasPrefix(evaluation.Signer.WorkflowRef, trustedWorkflowPrefix)
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
	if !trustedSigner(latest, repository) {
		return gemara.Failed, fmt.Sprintf("The latest result for %s/%s was signed by workflow %q from %q, not the %s publish workflow from %s", namespace, id, latest.Signer.WorkflowRef, latest.Signer.CallerRepository, strings.TrimSuffix(trustedWorkflowPrefix, "/"), repository), gemara.High
	}
	return gemara.Passed, fmt.Sprintf("grc.store target %s/%s is verified by GitHub OIDC and its latest result was signed by %s from %s", namespace, id, latest.Signer.WorkflowRef, repository), gemara.High
}

// LatestResultHasNoFailures requires every control of the newest published
// OSPS Baseline result that applies at the project's maturity level to have
// been evaluated without a failure. An Unknown result is the scanner erroring,
// not the project failing, so it needs review rather than failing the badge.
func LatestResultHasNoFailures(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	level, ok := reusable_steps.MaturityLevel(payload)
	if !ok {
		return gemara.NeedsReview, reusable_steps.MaturityLevelMissing, gemara.Low
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
	var failed, skipped, untagged, unknown, stale []string
	for _, entry := range entries {
		if !appliesAt(entry, level) {
			continue
		}
		switch {
		case staleFinding(latest, entry):
			stale = append(stale, fmt.Sprintf("%s %s", entry.Requirement.EntryID, entry.Result))
		case entry.Result == gemara.Failed.String():
			failed = append(failed, entry.Requirement.EntryID)
		case entry.Result == gemara.Unknown.String():
			unknown = append(unknown, unknownControl(entry))
		case entry.Result == gemara.NotRun.String() && entry.StepsExecuted == 0 && !slices.Contains(entry.Applicability, fmt.Sprintf("maturity-%d", level)):
			// The scanner skips a control its catalog does not tag with the scan's
			// level, so a scan at this level cannot evaluate it.
			untagged = append(untagged, entry.Requirement.EntryID)
		case entry.Result == gemara.NotRun.String() && entry.StepsExecuted == 0:
			skipped = append(skipped, entry.Requirement.EntryID)
		}
	}
	// A failure still fails, but the stale results are named beside it.
	var staleSuffix string
	if len(stale) > 0 {
		staleSuffix = "; separately, " + staleNote(latest, stale)
	}
	if len(failed) > 0 {
		return gemara.Failed, fmt.Sprintf("The latest OSPS Baseline result for %s/%s (%s) reports %d failed control(s) at maturity level %d: %s", namespace, id, resultLabel(latest), len(failed), level, strings.Join(failed, ", ")) + staleSuffix, gemara.High
	}
	if len(skipped) > 0 {
		return gemara.Failed, fmt.Sprintf("The latest OSPS Baseline result for %s/%s (%s) did not evaluate %d control(s) that apply at maturity level %d (%s); publish a scan at maturity level %d", namespace, id, resultLabel(latest), len(skipped), level, strings.Join(skipped, ", "), level) + staleSuffix, gemara.High
	}
	var gaps []string
	if len(untagged) > 0 {
		gaps = append(gaps, fmt.Sprintf("%d control(s) apply at maturity level %d but the scanner's catalog tags them only for lower levels, so the scan did not evaluate them; check them by hand: %s", len(untagged), level, strings.Join(untagged, ", ")))
	}
	if len(unknown) > 0 {
		gaps = append(gaps, unknownNote(unknown))
	}
	if len(stale) > 0 {
		gaps = append(gaps, staleNote(latest, stale))
	}
	if len(gaps) > 0 {
		return gemara.NeedsReview, fmt.Sprintf("The latest OSPS Baseline result for %s/%s (%s) has no failed controls at maturity level %d, but %s", namespace, id, resultLabel(latest), level, strings.Join(gaps, "; ")), gemara.Medium
	}
	return gemara.Passed, fmt.Sprintf("The latest OSPS Baseline result for %s/%s (%s) reports no failed controls at maturity level %d", namespace, id, resultLabel(latest), level), gemara.High
}

// AIReviewUncheckedControlEvidence asks the model whether the documentation
// linked from Security Insights covers the controls at the project's maturity
// level that the latest published result could not check (Needs Review and
// Not Run). Unknown controls are the scanner erroring, which no document can
// settle, so they are reported for a re-scan or a hand check instead.
func AIReviewUncheckedControlEvidence(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	level, ok := reusable_steps.MaturityLevel(payload)
	if !ok {
		return gemara.NeedsReview, reusable_steps.MaturityLevelMissing, gemara.Low
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
	var unknown, stale []string
	for _, entry := range entries {
		if appliesAt(entry, level) && staleFinding(latest, entry) {
			stale = append(stale, fmt.Sprintf("%s %s", entry.Requirement.EntryID, entry.Result))
			continue
		}
		if appliesAt(entry, level) && entry.Result == gemara.Unknown.String() {
			unknown = append(unknown, unknownControl(entry))
		}
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
	var notes []string
	if len(unknown) > 0 {
		notes = append(notes, unknownNote(unknown))
	}
	if len(stale) > 0 {
		notes = append(notes, staleNote(latest, stale))
	}
	if len(unchecked) == 0 {
		if len(notes) > 0 {
			return gemara.NeedsReview, fmt.Sprintf("The latest OSPS Baseline result for %s/%s (%s) has no Needs Review or Not Run controls at maturity level %d, but %s", namespace, id, resultLabel(latest), level, strings.Join(notes, "; ")), gemara.Medium
		}
		return gemara.Passed, fmt.Sprintf("The latest OSPS Baseline result for %s/%s (%s) has no Needs Review or Not Run controls at maturity level %d", namespace, id, resultLabel(latest), level), gemara.High
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
	incomplete := packet.Collection.Unretrieved
	for _, document := range packet.Documentation {
		if document.Truncated {
			incomplete = append(incomplete, document.URL+" truncated")
		}
	}
	result, message, confidence = reusable_steps.AIReview(payload, "defender-unchecked-control-evidence", string(material), sources, incomplete)
	// Only the last step's message reaches the log, so repeat the Unknowns and
	// stale scanner results here.
	if len(notes) > 0 {
		message += " Not covered by the AI review: " + strings.Join(notes, "; ")
		if result == gemara.Passed {
			result, confidence = gemara.NeedsReview, gemara.Medium
		}
	}
	return result, message, confidence
}

func unknownControl(entry assessmentLogEntry) string {
	return fmt.Sprintf("%s (%s)", entry.Requirement.EntryID, entry.Message)
}

// fixedScannerVersion is the first OSPS Baseline scanner release with
// ossf/pvtr-github-repo-scanner #519 (batched binary-scan fallback), #520
// (unknown workflow keys) and #521 (BR-07.01 and VM-02.01 at every level).
const fixedScannerVersion = "v0.33.1"

// resultLabel names a published result and the scanner version that made it.
func resultLabel(evaluation data.GrcStoreEvaluation) string {
	version := evaluation.EvaluatorPlugin.Version
	if version == "" {
		version = "unknown"
	}
	return fmt.Sprintf("%s, scanner %s", evaluation.LogVersion, version)
}

// staleFinding reports whether the entry is one of the scanner bugs fixed in
// fixedScannerVersion, in a result an older scanner made: the finding says
// nothing about the project. An unknown scanner version is not judged stale.
func staleFinding(evaluation data.GrcStoreEvaluation, entry assessmentLogEntry) bool {
	version := "v" + strings.TrimPrefix(evaluation.EvaluatorPlugin.Version, "v")
	if !semver.IsValid(version) || semver.Compare(version, fixedScannerVersion) >= 0 {
		return false
	}
	switch id := entry.Requirement.EntryID; {
	case id == "OSPS-QA-05.01" || id == "OSPS-QA-05.02":
		return entry.Result == gemara.Unknown.String()
	case id == "OSPS-BR-01.01":
		return entry.Result == gemara.NeedsReview.String() && strings.Contains(entry.Message, "unexpected key")
	case id == "OSPS-BR-07.01" || id == "OSPS-VM-02.01":
		return entry.Result == gemara.NotRun.String() && entry.StepsExecuted == 0
	}
	return false
}

// staleNote marks stale scanner results as such, not as project failures.
func staleNote(evaluation data.GrcStoreEvaluation, stale []string) string {
	return fmt.Sprintf("%d result(s) are stale scanner results, not project failures: scanner %s predates the fixes in %s, so re-publish with %s or later: %s", len(stale), evaluation.EvaluatorPlugin.Version, fixedScannerVersion, fixedScannerVersion, strings.Join(stale, ", "))
}

// unknownNote says which controls the scanner could not determine and what to do.
func unknownNote(unknown []string) string {
	return fmt.Sprintf("the scanner could not determine %d control(s); re-scan or check them by hand: %s", len(unknown), strings.Join(unknown, "; "))
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

// appliesAt reports whether a log entry belongs to the level. Baseline levels
// are cumulative, so a control tagged maturity-N applies at N and above: the
// 2026-08 catalog tags OSPS-BR-07.01 and OSPS-VM-02.01 maturity-1 only.
func appliesAt(entry assessmentLogEntry, level int) bool {
	return slices.ContainsFunc(entry.Applicability, func(tag string) bool {
		n, ok := strings.CutPrefix(tag, "maturity-")
		lowest, err := strconv.Atoi(n)
		return ok && err == nil && lowest >= 1 && lowest <= level
	})
}

// grcStoreTargetMissing is the message for steps that need grc_store_target.
const grcStoreTargetMissing = "Set the grc_store_target var to the project's grc.store target as <namespace>/<target>, the target the pvtr-publish-results workflow publishes to"

// declaredTarget reads the grc_store_target var, <namespace>/<target>. The
// reviewer sets it because projects are not asked to record it anywhere.
func declaredTarget(payload data.Payload) (namespace, id string, ok bool) {
	if payload.Config == nil {
		return "", "", false
	}
	namespace, id, ok = strings.Cut(strings.TrimSpace(payload.Config.GetString("grc_store_target")), "/")
	if !ok || namespace == "" || id == "" || strings.Contains(id, "/") {
		return "", "", false
	}
	return namespace, id, true
}

// loadTarget fetches the declared target. A nil target comes with the
// result and message the calling step should return.
func loadTarget(payload data.Payload) (target *data.GrcStoreTarget, namespace, id string, result gemara.Result, message string) {
	namespace, id, ok := declaredTarget(payload)
	if !ok {
		return nil, "", "", gemara.NeedsReview, grcStoreTargetMissing
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
