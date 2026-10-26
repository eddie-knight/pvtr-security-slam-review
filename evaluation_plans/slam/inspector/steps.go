package inspector

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
)

const behavior = "inspector-self-assessment-coverage"

// maxAssessmentContentBytes keeps the material well inside a model's context
// even for a long written assessment.
const maxAssessmentContentBytes = 48 * 1024

// maxLinkedDocuments caps the same-repository files linked from the evidence
// document that are sent with it, for an index page such as a README that
// lists the catalogs.
const maxLinkedDocuments = 8

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
	Complete    bool     `json:"complete"`
	Scope       string   `json:"scope"`
	Note        string   `json:"note,omitempty"`
	Unretrieved []string `json:"unretrieved,omitempty"`
}

type selfAssessmentAIEvidence struct {
	Project        projectIdentity            `json:"project"`
	SelfAssessment assessmentDeclaration      `json:"self_assessment_declaration"`
	Document       assessmentDocument         `json:"self_assessment"`
	Linked         []assessmentDocument       `json:"linked_documents,omitempty"`
	Collection     evidenceCollectionMetadata `json:"collection"`
}

const evidenceCollectionScope = "The document at the Security Insights repository.security.assessments.self.evidence URL, plus up to 8 files it links to in the same GitHub repository (linked_documents), in link order, within one shared content budget. Links to other sites, files those linked files reference, and repository files nothing links to were not retrieved. HTML pages are reduced to their text. Complete means every supplied document is whole and every same-repository link was retrieved, not that the assessment is current or accurate."

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
	budget := maxAssessmentContentBytes
	packet.Document.Content = documentContent(fetched, &budget, &packet.Collection)
	sources := []string{url}
	for i, link := range sameRepoLinks(url, string(fetched.Body)) {
		if i == maxLinkedDocuments || budget == 0 {
			packet.Collection.Complete = false
			packet.Collection.Unretrieved = append(packet.Collection.Unretrieved, link+" (limit reached)")
			continue
		}
		linked, err := fetchURL(&payload, link)
		switch {
		case err != nil:
			packet.Collection.Unretrieved = append(packet.Collection.Unretrieved, link+": "+err.Error())
		case linked.StatusCode < 200 || linked.StatusCode > 299:
			packet.Collection.Unretrieved = append(packet.Collection.Unretrieved, fmt.Sprintf("%s: HTTP %d", link, linked.StatusCode))
		default:
			packet.Linked = append(packet.Linked, assessmentDocument{SourceURL: link, FinalURL: linked.FinalURL, ContentType: linked.ContentType, Content: documentContent(linked, &budget, &packet.Collection)})
			sources = append(sources, link)
			continue
		}
		packet.Collection.Complete = false
	}
	if !packet.Collection.Complete {
		packet.Collection.Note = "Some content is missing: a document was truncated (its content ends early) or a linked file listed in unretrieved was not supplied."
	}

	material, err := json.Marshal(packet)
	if err != nil {
		return gemara.NeedsReview, "Self-assessment evidence could not be prepared for AI review: " + err.Error(), gemara.Low
	}
	return reusable_steps.AIReview(payload, behavior, string(material), sources)
}

// documentContent is the fetched text, HTML reduced to words, cut to what is
// left of budget. Truncation marks the collection incomplete.
func documentContent(fetched data.FetchedURL, budget *int, collection *evidenceCollectionMetadata) string {
	content := string(fetched.Body)
	if strings.Contains(strings.ToLower(fetched.ContentType), "text/html") {
		content = htmlToText(content)
	}
	if fetched.Truncated {
		collection.Complete = false
	}
	if len(content) > *budget {
		content = strings.ToValidUTF8(content[:*budget], "")
		collection.Complete = false
	}
	*budget -= len(content)
	return content
}

var documentLink = regexp.MustCompile(`\]\(\s*<?([^)\s>]+)|(?i)href\s*=\s*["']([^"']+)["']`)

// sameRepoLinks lists the links in a document at a github.com blob URL that
// resolve to other files in the same repository, in order, without
// duplicates or fragments.
// shortcut: only github.com blob evidence URLs; add raw.githubusercontent.com and docs sites if projects declare those as index pages.
func sameRepoLinks(evidenceURL, body string) []string {
	base, err := url.Parse(evidenceURL)
	if err != nil || !strings.EqualFold(base.Host, "github.com") {
		return nil
	}
	parts := strings.SplitN(base.Path, "/", 5) // "", owner, repo, "blob", rest
	if len(parts) != 5 || parts[3] != "blob" {
		return nil
	}
	prefix := strings.ToLower(strings.Join(parts[:4], "/") + "/")
	base.Fragment, base.RawQuery = "", ""
	seen := map[string]bool{base.String(): true}
	var links []string
	for _, match := range documentLink.FindAllStringSubmatch(body, -1) {
		ref, err := url.Parse(html.UnescapeString(match[1] + match[2]))
		if err != nil {
			continue
		}
		link := base.ResolveReference(ref)
		link.Fragment, link.RawQuery = "", ""
		if link.Scheme != "https" || !strings.EqualFold(link.Host, "github.com") || !strings.HasPrefix(strings.ToLower(link.Path), prefix) || strings.HasSuffix(link.Path, "/") || seen[link.String()] {
			continue
		}
		seen[link.String()] = true
		links = append(links, link.String())
	}
	return links
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
