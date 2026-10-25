package cra

import (
	"encoding/json"
	"fmt"
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

const collectionScope = "The security policy and (unless scope is out_of_scope) the contributing guide linked from Security Insights, falling back to the repository files listed in each document's \"candidates\". Links within those documents were not followed. The badge page asks for no separate readiness checklist document, so none was retrieved."

var (
	fetchURL       = (*data.Payload).FetchURL
	getFileContent = (*data.Payload).GetFileContent

	securityPolicyFiles    = []string{"SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"}
	contributingGuideFiles = []string{"CONTRIBUTING.md", ".github/CONTRIBUTING.md", "docs/CONTRIBUTING.md"}
)

// SecurityInsightsLinksPresent checks the Security Insights entries the badge
// page asks for: the security policy, the contributing guide, and that reports
// are accepted. An out-of-scope project owes only the security policy.
func SecurityInsightsLinksPresent(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if securityPolicyURL(payload.Insights) == "" {
		return gemara.Failed, "Security Insights is incomplete for CRA Readiness: project.vulnerability-reporting.policy (or repository.documentation.security-policy) is missing", gemara.High
	}
	if policy, _ := securityPolicy(&payload); scopeOf(policy.Content) == outOfScope {
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
		return gemara.Failed, "Security Insights is incomplete for CRA Readiness: " + strings.Join(problems, "; "), gemara.High
	}
	return gemara.Passed, "Security Insights links the security policy and contributing guide and accepts vulnerability reports", gemara.High
}

// SecurityPolicyHasStewardStatement checks that the security policy carries
// the LF CRA stewardship statement, or the out-of-scope sentence, verbatim.
func SecurityPolicyHasStewardStatement(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	policy, checked := securityPolicy(&payload)
	if len(checked) == 0 {
		return gemara.Failed, fmt.Sprintf("No security policy could be retrieved from Security Insights or %s", strings.Join(securityPolicyFiles, ", ")), gemara.High
	}
	switch scopeOf(policy.Content) {
	case inScope:
		return gemara.Passed, "The LF CRA stewardship statement appears verbatim in " + policy.Source, gemara.High
	case outOfScope:
		return gemara.Passed, "The CRA out-of-scope statement appears verbatim in " + policy.Source, gemara.High
	}
	return gemara.Failed, "Neither the LF CRA stewardship statement nor the out-of-scope statement appears verbatim in " + strings.Join(checked, ", "), gemara.High
}

// AIReviewReadiness grades whether the steward's asks are met in substance:
// a real reporting process below the statement and the escalation section.
// An out-of-scope project owes neither, so its contributing guide is not read.
func AIReviewReadiness(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	insights := payload.Insights
	reporting := insights.Project.VulnerabilityReporting
	policy, _ := securityPolicy(&payload)
	packet := material{
		Scope:          scopeOf(policy.Content),
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
	return reusable_steps.AIReview(payload, "cra-readiness-quality", string(raw), sources)
}

type document struct {
	Role       string   `json:"role"`
	Candidates []string `json:"candidates"`
	Source     string   `json:"source,omitempty"`
	Content    string   `json:"content,omitempty"`
	Truncated  bool     `json:"truncated,omitempty"`
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
// first readable one, plus every candidate that was read. The declared link
// often lives in an org-level .github repository, so it is tried first.
func securityPolicy(payload *data.Payload) (document, []string) {
	sources := candidates(securityPolicyURL(payload.Insights), securityPolicyFiles)
	found := document{Role: "security_policy", Candidates: sources}
	var checked []string
	for _, source := range sources {
		doc := readDocument(payload, found.Role, []string{source})
		if doc.Source == "" {
			continue
		}
		doc.Candidates = sources
		checked = append(checked, source)
		if scopeOf(doc.Content) != "" {
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

// scopeOf reports which statement text carries, the LF statement winning.
// Matching is verbatim except for whitespace, so markdown line wrapping does
// not matter.
func scopeOf(text string) string {
	collapsed := strings.Join(strings.Fields(text), " ")
	switch {
	case strings.Contains(collapsed, StewardStatement):
		return inScope
	case strings.Contains(collapsed, OutOfScopeStatement):
		return outOfScope
	}
	return ""
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
