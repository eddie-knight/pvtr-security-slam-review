package inspector

import (
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strings"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/reusable_steps"
	"github.com/gemaraproj/go-gemara"
)

const behavior = "inspector-self-assessment-coverage"

// maxAssessmentContentBytes keeps the material well inside a model's context
// even for a long written assessment.
const maxAssessmentContentBytes = 48 * 1024

var fetchURL = (*data.Payload).FetchURL

func selfAssessmentURL(payload data.Payload) string {
	evidence := payload.Insights.Repository.SecurityPosture.Assessments.Self.Evidence
	if evidence == nil {
		return ""
	}
	return strings.TrimSpace(string(*evidence))
}

// SelfAssessmentDeclared requires an evidence URL: a comment alone ("in
// progress") or a name alone gives reviewers nothing to read.
func SelfAssessmentDeclared(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	if url := selfAssessmentURL(payload); url != "" {
		return gemara.Passed, "Self-assessment declared in Security Insights: " + url, gemara.High
	}
	if comment := strings.TrimSpace(payload.Insights.Repository.SecurityPosture.Assessments.Self.Comment); comment != "" {
		return gemara.Failed, fmt.Sprintf("Security Insights repository.security.assessments.self has no evidence URL; its comment says: %q", comment), gemara.High
	}
	return gemara.Failed, "Security Insights does not declare a self-assessment at repository.security.assessments.self.evidence", gemara.High
}

func SelfAssessmentResolves(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	url := selfAssessmentURL(payload)
	fetched, err := fetchURL(&payload, url)
	if err != nil {
		return gemara.Failed, fmt.Sprintf("Self-assessment %s could not be fetched: %s", url, err), gemara.Medium
	}
	if fetched.StatusCode < 200 || fetched.StatusCode > 299 {
		return gemara.Failed, fmt.Sprintf("Self-assessment %s does not resolve (HTTP %d)", url, fetched.StatusCode), gemara.High
	}
	return gemara.Passed, "Self-assessment resolves: " + url, gemara.High
}

type assessmentDeclaration struct {
	Name     string `json:"name,omitempty"`
	Comment  string `json:"comment,omitempty"`
	Date     string `json:"date,omitempty"`
	Evidence string `json:"evidence_url"`
}

type projectIdentity struct {
	Name              string `json:"name,omitempty"`
	RepositoryURL     string `json:"repository_url,omitempty"`
	ScannedRepository string `json:"scanned_repository"`
}

type assessmentDocument struct {
	SourceURL   string `json:"source_url"`
	FinalURL    string `json:"final_url,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	Content     string `json:"content"`
}

type evidenceCollectionMetadata struct {
	Complete bool   `json:"complete"`
	Scope    string `json:"scope"`
	Note     string `json:"note,omitempty"`
}

type selfAssessmentAIEvidence struct {
	Project        projectIdentity            `json:"project"`
	SelfAssessment assessmentDeclaration      `json:"self_assessment_declaration"`
	Document       assessmentDocument         `json:"self_assessment"`
	Collection     evidenceCollectionMetadata `json:"collection"`
}

const evidenceCollectionScope = "Only the single document at the Security Insights repository.security.assessments.self.evidence URL. Links within it, other repository files, and companion files (such as a Gemara capability catalog referenced by a threat catalog) were not retrieved. HTML pages are reduced to their text. Complete means the whole declared document was supplied, not that the assessment is current or accurate."

func AIReviewSelfAssessment(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	url := selfAssessmentURL(payload)
	fetched, err := fetchURL(&payload, url)
	if err != nil {
		return gemara.NeedsReview, fmt.Sprintf("Self-assessment %s could not be fetched for AI review: %s", url, err), gemara.Low
	}

	self := payload.Insights.Repository.SecurityPosture.Assessments.Self
	packet := selfAssessmentAIEvidence{
		Project: projectIdentity{
			Name:              payload.Insights.Project.Name,
			RepositoryURL:     string(payload.Insights.Repository.Url),
			ScannedRepository: payload.Owner + "/" + payload.Repo,
		},
		SelfAssessment: assessmentDeclaration{Comment: self.Comment, Date: string(self.Date), Evidence: url},
		Document:       assessmentDocument{SourceURL: url, FinalURL: fetched.FinalURL, ContentType: fetched.ContentType},
		Collection:     evidenceCollectionMetadata{Complete: !fetched.Truncated, Scope: evidenceCollectionScope},
	}
	if self.Name != nil {
		packet.SelfAssessment.Name = *self.Name
	}
	content := string(fetched.Body)
	if strings.Contains(strings.ToLower(fetched.ContentType), "text/html") {
		content = htmlToText(content)
	}
	if len(content) > maxAssessmentContentBytes {
		content = strings.ToValidUTF8(content[:maxAssessmentContentBytes], "")
		packet.Collection.Complete = false
	}
	packet.Document.Content = content
	if !packet.Collection.Complete {
		packet.Collection.Note = "The document was truncated; the content ends before the end of the declared document."
	}

	material, err := json.Marshal(packet)
	if err != nil {
		return gemara.NeedsReview, "Self-assessment evidence could not be prepared for AI review: " + err.Error(), gemara.Low
	}
	return reusable_steps.AIReview(payload, behavior, string(material), []string{url})
}

var (
	htmlHiddenElement = regexp.MustCompile(`(?is)<(script|style|noscript|svg|head)\b.*?</(script|style|noscript|svg|head)\s*>`)
	htmlTag           = regexp.MustCompile(`(?s)<[^>]*>`)
	blankRun          = regexp.MustCompile(`[ \t]*\n[\s]*`)
	spaceRun          = regexp.MustCompile(`[ \t]+`)
)

// htmlToText drops markup so the model's budget goes to the assessment's
// words, not a docs site's navigation scripts and styles.
// shortcut: regexp stripping, not an HTML parser; upgrade to x/net/html if
// pages with tags inside attributes or comments garble the text.
func htmlToText(page string) string {
	text := htmlHiddenElement.ReplaceAllString(page, " ")
	text = htmlTag.ReplaceAllString(text, "\n")
	text = html.UnescapeString(text)
	text = spaceRun.ReplaceAllString(text, " ")
	return strings.TrimSpace(blankRun.ReplaceAllString(text, "\n"))
}
