package cra

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/reusable_steps"
	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
)

// StewardStatement is the LF CRA stewardship statement, copied verbatim from
// the CRA Readiness badge page.
const StewardStatement = `CRA stewardship: This project is supported under the Linux Foundation CRA stewardship framework, as described at https://www.linuxfoundation.org/security. Security vulnerabilities should be reported through the mechanisms described below, which we will coordinate with our CRA steward. For actively exploited vulnerabilities and severe incidents that may require CRA escalation, please use the project's emergency security reporting mechanisms as appropriate.`

// OutOfScopeStatement is the badge page's sentence for projects that release
// nothing intended for commercial products, copied verbatim.
const OutOfScopeStatement = `We do not anticipate this project being used in commercial products. See [LF-Supported Projects and CRA Readiness](https://openssf.org/wp-content/uploads/2026/09/LF-Supported-Projects-and-CRA-Readiness-2026-09-10.pdf) for more information.`

const (
	inScope    = "in_scope"
	outOfScope = "out_of_scope"
)

// maxDocumentBytes caps each document sent for AI review.
const maxDocumentBytes = 24 * 1024

const collectionScope = "The security policy linked from Security Insights (the repository files in \"candidates\" only when no policy is linked) and, unless scope is out_of_scope, the contributing guide linked from Security Insights, falling back to the repository files in its \"candidates\". HTML pages were reduced to text. Links within those documents were not followed. The badge page asks for no separate readiness checklist document, so none was retrieved."

var (
	fetchURL                = (*data.Payload).FetchURL
	getFileContent          = (*data.Payload).GetFileContent
	privateReportingEnabled = (*data.Payload).PrivateReportingEnabled

	securityPolicyFiles    = []string{"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"}
	contributingGuideFiles = []string{"CONTRIBUTING.md", ".github/CONTRIBUTING.md", "docs/CONTRIBUTING.md"}
)

// SecurityInsightsLinksPresent checks the Security Insights entries the badge
// page asks for: the security policy, the contributing guide, and that reports
// are accepted. An out-of-scope project owes only the security policy.
func SecurityInsightsLinksPresent(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if note, other := otherSteward(payload); other {
		return gemara.NeedsReview, note, gemara.Medium
	}
	if securityPolicyURL(payload.Insights) == "" {
		return failed(&payload, "Security Insights is incomplete for CRA Readiness: project.vulnerability-reporting.policy (or repository.documentation.security-policy) is missing")
	}
	if policy, _ := securityPolicy(&payload); scopeOf(policy) == outOfScope {
		return gemara.Passed, "Security Insights links the security policy, which declares the project out of CRA scope", gemara.High
	}
	var problems []string
	if siURL(payload.Insights.Repository.Documentation.ContributingGuide) == "" {
		problems = append(problems, "repository.documentation.contributing-guide is missing")
	}
	if !payload.Insights.Project.VulnerabilityReporting.ReportsAccepted {
		problems = append(problems, "project.vulnerability-reporting.reports-accepted is not true")
	}
	if len(problems) > 0 {
		return failed(&payload, "Security Insights is incomplete for CRA Readiness: "+strings.Join(problems, "; "))
	}
	return gemara.Passed, "Security Insights links the security policy and contributing guide and accepts vulnerability reports", gemara.High
}

// SecurityPolicyHasStewardStatement checks that the security policy carries
// the LF CRA stewardship statement, or the out-of-scope sentence, verbatim.
func SecurityPolicyHasStewardStatement(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if note, other := otherSteward(payload); other {
		return gemara.NeedsReview, note, gemara.Medium
	}
	policy, checked := securityPolicy(&payload)
	if len(checked) == 0 {
		if linked := securityPolicyURL(payload.Insights); linked != "" {
			return failed(&payload, "The security policy linked from Security Insights could not be retrieved: "+linked)
		}
		return failed(&payload, fmt.Sprintf("No security policy could be retrieved from Security Insights or %s", strings.Join(securityPolicyFiles, ", ")))
	}
	switch scopeOf(policy) {
	case inScope:
		return gemara.Passed, "The LF CRA stewardship statement appears verbatim in " + policy.Source, gemara.High
	case outOfScope:
		return gemara.Passed, "The CRA out-of-scope statement appears verbatim in " + policy.Source, gemara.High
	}
	return failed(&payload, "Neither the LF CRA stewardship statement nor the out-of-scope statement appears verbatim in "+strings.Join(checked, ", "))
}

// StewardAddress is where the LF steward takes escalations.
const StewardAddress = "steward@linuxfoundation.org"

// advisoryForm finds a GitHub private vulnerability reporting link.
var advisoryForm = regexp.MustCompile(`(?i)github\.com/([\w.-]+)/([\w.-]+)/security/advisories/new`)

// ReportingChannelsWork checks what an in-scope project's documents promise
// that can be checked without a model: a GitHub private vulnerability
// reporting link in the policy or Security Insights points at a repository
// where it is switched on, and the contributing guide names the steward
// address. An out-of-scope project owes neither.
func ReportingChannelsWork(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if note, other := otherSteward(payload); other {
		return gemara.NeedsReview, note, gemara.Medium
	}
	policy, _ := securityPolicy(&payload)
	if scopeOf(policy) == outOfScope {
		return gemara.Passed, "The project is out of CRA scope; no reporting channel or escalation path is owed", gemara.High
	}
	var problems, unchecked []string
	text := policy.Content + "\n" + deref(payload.Insights.Project.VulnerabilityReporting.Comment)
	for _, form := range advisoryForm.FindAllStringSubmatch(text, -1) {
		enabled, err := privateReportingEnabled(&payload, form[1], form[2])
		switch {
		case err != nil:
			unchecked = append(unchecked, fmt.Sprintf("%s/%s: %s", form[1], form[2], err))
		case !enabled:
			problems = append(problems, fmt.Sprintf("GitHub private vulnerability reporting is named as a channel but is not enabled on %s/%s", form[1], form[2]))
		}
	}
	contributing := readDocument(&payload, "contributing_guide", candidates(siURL(payload.Insights.Repository.Documentation.ContributingGuide), contributingGuideFiles))
	if contributing.Source != "" && !strings.Contains(strings.ToLower(contributing.Content), StewardAddress) {
		problems = append(problems, fmt.Sprintf("the contributing guide %s does not name the steward escalation address %s", contributing.Source, StewardAddress))
	}
	if len(problems) > 0 {
		return failed(&payload, "CRA reporting and escalation channels: "+strings.Join(problems, "; "))
	}
	if len(unchecked) > 0 {
		return gemara.NeedsReview, "Could not check GitHub private vulnerability reporting: " + strings.Join(unchecked, "; "), gemara.Low
	}
	return gemara.Passed, "The named reporting channels are enabled and the contributing guide names " + StewardAddress, gemara.High
}

// lfStewardHosts are the Linux Foundation and the foundations it hosts, whose
// projects follow the LF CRA guidance.
// shortcut: the foundations seen so far; add one when its project is marked for review by mistake.
var lfStewardHosts = []string{"linuxfoundation.org", "cncf.io", "openssf.org", "lfaidata.foundation", "lfenergy.org", "finos.org", "hyperledger.org", "lfdecentralizedtrust.org", "cd.foundation", "openjsf.org", "graphql.org", "pytorch.org"}

// otherSteward reports a project whose Security Insights names a steward
// outside the LF: it follows that steward's guidance, which the plugin does
// not know, so it is marked for review rather than judged by the LF's asks.
// A project with no steward declared is judged as an LF project.
func otherSteward(payload data.Payload) (string, bool) {
	steward := payload.Insights.Project.Steward
	if steward == nil || strings.TrimSpace(steward.Uri) == "" {
		return "", false
	}
	u, err := url.Parse(strings.TrimSpace(steward.Uri))
	if err != nil {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	for _, lf := range lfStewardHosts {
		if host == lf || strings.HasSuffix(host, "."+lf) {
			return "", false
		}
	}
	return fmt.Sprintf("Security Insights names %s as the project's steward, not the Linux Foundation; check the project against that steward's CRA guidance by hand.%s", steward.Uri, reviewLink(&payload)), true
}

// failed returns a Failed result with the security policy's link, so the
// policy can be reviewed by hand.
func failed(payload *data.Payload, message string) (gemara.Result, string, gemara.ConfidenceLevel) {
	return gemara.Failed, message + "." + reviewLink(payload), gemara.High
}

// reviewLink names the declared security policy, else the first SECURITY.md
// candidate in the repository, else says there is none.
func reviewLink(payload *data.Payload) string {
	if linked := securityPolicyURL(payload.Insights); linked != "" {
		return " Security policy for review: " + linked
	}
	for _, path := range securityPolicyFiles {
		if _, err := getFileContent(payload, path); err == nil {
			return fmt.Sprintf(" Security policy for review: https://github.com/%s/%s/blob/%s/%s", payload.Owner, payload.Repo, payload.DefaultBranch, path)
		}
	}
	return " No security policy found to review."
}

// AIReviewReadiness grades whether the steward's asks are met in substance:
// a real reporting process below the statement and the escalation section.
// An out-of-scope project owes neither, so its contributing guide is not read.
func AIReviewReadiness(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if note, other := otherSteward(payload); other {
		return gemara.NeedsReview, note, gemara.Medium
	}
	insights := payload.Insights
	reporting := insights.Project.VulnerabilityReporting
	policy, _ := securityPolicy(&payload)
	packet := material{
		Scope:          scopeOf(policy),
		SecurityPolicy: capDocument(policy),
		SecurityInsights: insightsDeclarations{
			ReportsAccepted:   reporting.ReportsAccepted,
			Policy:            securityPolicyURL(insights),
			ContributingGuide: siURL(insights.Repository.Documentation.ContributingGuide),
			ContactName:       reporting.Contact.Name,
			ContactEmail:      email(reporting.Contact.Email),
			Comment:           deref(reporting.Comment),
		},
		Collection: collection{Complete: true, Scope: collectionScope},
	}
	docs := []document{packet.SecurityPolicy}
	if packet.Scope != outOfScope {
		contributing := capDocument(readDocument(&payload, "contributing_guide",
			candidates(siURL(insights.Repository.Documentation.ContributingGuide), contributingGuideFiles)))
		packet.ContributingGuide = &contributing
		docs = append(docs, contributing)
	}
	for _, doc := range docs {
		switch {
		case doc.Source == "":
			packet.Collection.Complete = false
			packet.Collection.Notes = append(packet.Collection.Notes, doc.Role+" could not be retrieved from any candidate")
		case doc.Truncated:
			packet.Collection.Complete = false
			packet.Collection.Notes = append(packet.Collection.Notes, fmt.Sprintf("%s truncated to %d bytes", doc.Role, maxDocumentBytes))
		}
	}
	raw, err := json.Marshal(packet)
	if err != nil {
		return gemara.Unknown, "Failed to assemble CRA readiness material: " + err.Error(), gemara.Low
	}
	var sources []string
	for _, doc := range docs {
		if doc.Source != "" {
			sources = append(sources, doc.Source)
		}
	}
	result, message, confidence = reusable_steps.AIReview(payload, "cra-readiness-quality", string(raw), sources, packet.Collection.Notes)
	if result == gemara.Failed {
		message += reviewLink(&payload)
	}
	return result, message, confidence
}

type document struct {
	Role       string   `json:"role"`
	Candidates []string `json:"candidates"`
	Source     string   `json:"source,omitempty"`
	Content    string   `json:"content,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"`
	// Rendered marks content reduced from an HTML page.
	Rendered bool `json:"-"`
}

type insightsDeclarations struct {
	ReportsAccepted   bool   `json:"reports_accepted"`
	Policy            string `json:"policy_url,omitempty"`
	ContributingGuide string `json:"contributing_guide_url,omitempty"`
	ContactName       string `json:"contact_name,omitempty"`
	ContactEmail      string `json:"contact_email,omitempty"`
	Comment           string `json:"comment,omitempty"`
}

type collection struct {
	Complete bool     `json:"complete"`
	Scope    string   `json:"scope"`
	Notes    []string `json:"notes,omitempty"`
}

type material struct {
	Scope             string               `json:"scope"`
	SecurityPolicy    document             `json:"security_policy"`
	ContributingGuide *document            `json:"contributing_guide,omitempty"`
	SecurityInsights  insightsDeclarations `json:"security_insights"`
	Collection        collection           `json:"collection"`
}

// securityPolicy returns the first candidate carrying either statement, else the
// first readable one, plus every candidate that was read. A policy linked from
// Security Insights is the only candidate: the badge page checks that the link
// points at the policy carrying the statement. The repository files are tried
// only when nothing is linked.
func securityPolicy(payload *data.Payload) (document, []string) {
	sources := securityPolicyFiles
	if linked := securityPolicyURL(payload.Insights); linked != "" {
		sources = []string{linked}
	}
	found := document{Role: "security_policy", Candidates: sources}
	var checked []string
	for _, source := range sources {
		doc := readDocument(payload, found.Role, []string{source})
		if doc.Source == "" {
			continue
		}
		doc.Candidates = sources
		checked = append(checked, source)
		if scopeOf(doc) != "" {
			return doc, checked
		}
		if found.Source == "" {
			found = doc
		}
	}
	return found, checked
}

// readDocument returns the first candidate that can be read: http(s) URLs via
// FetchURL (2xx only), anything else as a repository path.
func readDocument(payload *data.Payload, role string, sources []string) document {
	doc := document{Role: role, Candidates: sources}
	for _, source := range sources {
		if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
			fetched, err := fetchURL(payload, source)
			if err == nil && fetched.StatusCode >= 200 && fetched.StatusCode < 300 {
				doc.Source, doc.Content, doc.Truncated = source, string(fetched.Body), fetched.Truncated
				if isHTML(fetched) {
					doc.Content, doc.Rendered = htmlToText(doc.Content), true
				}
				return doc
			}
			continue
		}
		if content, err := getFileContent(payload, source); err == nil {
			doc.Source, doc.Content = source, string(content)
			return doc
		}
	}
	return doc
}

func capDocument(doc document) document {
	if len(doc.Content) > maxDocumentBytes {
		doc.Content, doc.Truncated = doc.Content[:maxDocumentBytes], true
	}
	return doc
}

// renderedOutOfScope is OutOfScopeStatement as a rendered page shows it: the
// markdown link reduced to its text.
var renderedOutOfScope = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`).ReplaceAllString(OutOfScopeStatement, "$1")

// scopeOf reports which statement the document carries, the LF statement
// winning. Matching is verbatim except for whitespace, so markdown line
// wrapping does not matter.
func scopeOf(doc document) string {
	collapsed := strings.Join(strings.Fields(doc.Content), " ")
	switch {
	case strings.Contains(collapsed, StewardStatement):
		return inScope
	case strings.Contains(collapsed, OutOfScopeStatement),
		doc.Rendered && strings.Contains(collapsed, renderedOutOfScope):
		return outOfScope
	}
	return ""
}

var (
	htmlSkipped = regexp.MustCompile(`(?is)<(script|style|noscript|svg|head)\b.*?</(script|style|noscript|svg|head)\s*>|<!--.*?-->`)
	htmlBlock   = regexp.MustCompile(`(?i)</?(br|p|div|h[1-6]|li|ul|ol|tr|td|th|table|pre|blockquote|section|article)\b[^>]*>`)
	htmlTag     = regexp.MustCompile(`(?s)<[^>]*>`)
)

func isHTML(fetched data.FetchedURL) bool {
	if strings.Contains(strings.ToLower(fetched.ContentType), "html") {
		return true
	}
	start := strings.ToLower(strings.TrimSpace(string(fetched.Body[:min(len(fetched.Body), 512)])))
	return strings.HasPrefix(start, "<!doctype html") || strings.HasPrefix(start, "<html")
}

// htmlToText reduces a page to its text. Inline tags vanish without a space,
// so a statement whose URL was auto-linked still matches verbatim. shortcut:
// regexes, not a parser; switch to x/net/html if markup leaks into the text.
func htmlToText(page string) string {
	page = htmlSkipped.ReplaceAllString(page, " ")
	page = htmlBlock.ReplaceAllString(page, "\n")
	return html.UnescapeString(htmlTag.ReplaceAllString(page, ""))
}

func candidates(declared string, files []string) []string {
	if declared == "" {
		return files
	}
	return append([]string{declared}, files...)
}

func securityPolicyURL(insights si.SecurityInsights) string {
	reporting := insights.Project.VulnerabilityReporting
	for _, u := range []*si.URL{reporting.Policy, reporting.SecurityPolicy, insights.Repository.Documentation.SecurityPolicy} {
		if s := siURL(u); s != "" {
			return s
		}
	}
	return ""
}

func siURL(u *si.URL) string {
	if u == nil {
		return ""
	}
	return strings.TrimSpace(string(*u))
}

func email(e *si.Email) string {
	if e == nil {
		return ""
	}
	return string(*e)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
