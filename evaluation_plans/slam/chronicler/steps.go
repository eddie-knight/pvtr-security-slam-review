package chronicler

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/reusable_steps"
	"github.com/gemaraproj/go-gemara"
	"github.com/ossf/si-tooling/v2/si"
)

// fetchURL is a test hook for fetching declared documentation.
var fetchURL = (*data.Payload).FetchURL

const (
	// Whole pages must reach the model: Meshery's GOVERNANCE.md is 56K
	// characters and its build-and-release page 47K; one project's declared
	// documents run to about 235K.
	maxDocumentChars = 64 * 1024
	maxMaterialChars = 256 * 1024
	// A declared document this short is likely a pointer elsewhere (Meshery's
	// SECURITY.md only links to its docs site), so its links are followed.
	maxDelegatingChars = 2 * 1024
	maxFollowedLinks   = 3
)

// docLink is one documentation URL declared in Security Insights, with the
// topic it is declared for and the OSPS Baseline controls it serves.
type docLink struct {
	Field    string `json:"field"`
	Topic    string `json:"topic"`
	Controls string `json:"osps_controls,omitempty"`
	URL      string `json:"-"`
}

// declaredDocs lists every documentation-shaped link in Security Insights:
//
//	SI field                                         | documents                          | OSPS controls
//	project.documentation.quickstart-guide           | user guide for basic functionality | DO-01.01 (L1)
//	project.documentation.detailed-guide             | user guide for basic functionality | DO-01.01 (L1)
//	repository.documentation.contributing-guide      | contribution process               | GV-03.01 (L1), GV-03.02 (L2)
//	project.vulnerability-reporting.policy           | security policy and contacts       | VM-02.01 (L1), VM-01.01, VM-03.01, VM-04.01 (L2)
//	repository.documentation.security-policy         | security policy and contacts       | VM-02.01 (L1), VM-01.01, VM-03.01, VM-04.01 (L2)
//	repository.documentation.governance              | members, roles, responsibilities   | GV-01.01, GV-01.02 (L2)
//	repository.documentation.dependency-management-policy | dependency selection and tracking | DO-06.01 (L2)
//	repository.documentation.review-policy           | change review process              | -
//	project.documentation.signature-verification     | release verification               | DO-03.01, DO-03.02 (L3)
//	project.documentation.support-policy             | support scope and end of updates   | DO-04.01, DO-05.01 (L3)
//	project.documentation.release-process            | release process                    | -
//	project.documentation.design                     | system design                      | SA-01.01 (L2)
//	project.documentation.code-of-conduct            | conduct guidelines                 | -
//	repository.release.changelog                     | release changelog                  | BR-04.01 (L2)
//
// Fields not set have an empty URL.
func docFields(insights si.SecurityInsights) []docLink {
	project, repo := insights.Project.Documentation, insights.Repository.Documentation
	vuln := insights.Project.VulnerabilityReporting
	security := "security policy: how to report vulnerabilities privately, security contacts, disclosure process"
	candidates := []struct {
		link docLink
		url  *si.URL
	}{
		{docLink{Field: "project.documentation.quickstart-guide", Topic: "user guide for basic functionality", Controls: "OSPS-DO-01.01"}, project.QuickstartGuide},
		{docLink{Field: "project.documentation.detailed-guide", Topic: "user guide for basic functionality", Controls: "OSPS-DO-01.01"}, project.DetailedGuide},
		{docLink{Field: "repository.documentation.contributing-guide", Topic: "contribution process and requirements", Controls: "OSPS-GV-03.01, OSPS-GV-03.02"}, repo.ContributingGuide},
		{docLink{Field: "project.vulnerability-reporting.policy", Topic: security, Controls: "OSPS-VM-01.01, OSPS-VM-02.01, OSPS-VM-03.01, OSPS-VM-04.01"}, vuln.Policy},
		{docLink{Field: deprecatedSecurityPolicy, Topic: security, Controls: "OSPS-VM-01.01, OSPS-VM-02.01, OSPS-VM-03.01, OSPS-VM-04.01"}, vuln.SecurityPolicy},
		{docLink{Field: "repository.documentation.security-policy", Topic: security, Controls: "OSPS-VM-01.01, OSPS-VM-02.01, OSPS-VM-03.01, OSPS-VM-04.01"}, repo.SecurityPolicy},
		{docLink{Field: "repository.documentation.governance", Topic: "project members, roles, and responsibilities", Controls: "OSPS-GV-01.01, OSPS-GV-01.02"}, repo.Governance},
		{docLink{Field: "repository.documentation.dependency-management-policy", Topic: "how dependencies are selected, obtained, and tracked", Controls: "OSPS-DO-06.01"}, repo.DependencyManagementPolicy},
		{docLink{Field: "repository.documentation.review-policy", Topic: "process for reviewing changes"}, repo.ReviewPolicy},
		{docLink{Field: "project.documentation.signature-verification", Topic: "how to verify release integrity and the identity of the release author", Controls: "OSPS-DO-03.01, OSPS-DO-03.02"}, project.SignatureVerification},
		{docLink{Field: "project.documentation.support-policy", Topic: "scope and duration of support, and when versions stop receiving security updates", Controls: "OSPS-DO-04.01, OSPS-DO-05.01"}, project.SupportPolicy},
		{docLink{Field: "project.documentation.release-process", Topic: "how releases are planned, prepared, and published"}, project.ReleaseProcess},
		{docLink{Field: "project.documentation.design", Topic: "system design: actors and actions", Controls: "OSPS-SA-01.01"}, project.Design},
		{docLink{Field: "project.documentation.code-of-conduct", Topic: "contributor and user conduct guidelines"}, project.CodeOfConduct},
		{docLink{Field: "repository.release.changelog", Topic: "release changelog of functional and security changes", Controls: "OSPS-BR-04.01"}, insights.Repository.ReleaseDetails.Changelog},
	}
	links := make([]docLink, len(candidates))
	for i, c := range candidates {
		links[i] = c.link
		if c.url != nil {
			links[i].URL = strings.TrimSpace(string(*c.url))
		}
	}
	return links
}

func declaredDocs(insights si.SecurityInsights) []docLink {
	var links []docLink
	for _, link := range docFields(insights) {
		if link.URL != "" {
			links = append(links, link)
		}
	}
	return links
}

// deprecatedSecurityPolicy is the pre-v2.2 name of
// project.vulnerability-reporting.policy; its absence is not worth reporting.
const deprecatedSecurityPolicy = "project.vulnerability-reporting.security-policy"

// level1Docs are the Maturity Level 1 documentation controls with a Security
// Insights home: DO-01.01 (user guide), GV-03.01 (contributing guide), and
// VM-02.01 (security policy). Any one field of a group satisfies it.
var level1Docs = []struct {
	name   string
	fields []string
}{
	{"user guide (project.documentation.quickstart-guide or detailed-guide)", []string{"project.documentation.quickstart-guide", "project.documentation.detailed-guide"}},
	{"contributing guide (repository.documentation.contributing-guide)", []string{"repository.documentation.contributing-guide"}},
	{"security policy (project.vulnerability-reporting.policy or repository.documentation.security-policy)", []string{"project.vulnerability-reporting.policy", deprecatedSecurityPolicy, "repository.documentation.security-policy"}},
}

func DocumentationLinksPresent(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	links := declaredDocs(payload.Insights)
	declared := map[string]bool{}
	for _, link := range links {
		declared[link.Field] = true
	}
	var missing []string
	for _, doc := range level1Docs {
		found := false
		for _, field := range doc.fields {
			found = found || declared[field]
		}
		if !found {
			missing = append(missing, doc.name)
		}
	}
	if len(missing) > 0 {
		return gemara.Failed, "Security Insights does not link the Maturity Level 1 documentation: " + strings.Join(missing, "; "), gemara.High
	}
	var present, absent []string
	for _, link := range docFields(payload.Insights) {
		switch {
		case link.URL != "":
			present = append(present, link.Field)
		case link.Field != deprecatedSecurityPolicy:
			absent = append(absent, link.Field)
		}
	}
	message = "Security Insights links the Maturity Level 1 documentation; declared: " + strings.Join(present, ", ")
	if len(absent) > 0 {
		message += "; not declared: " + strings.Join(absent, ", ")
	}
	return gemara.Passed, message, gemara.High
}

// isTemplated reports a URL with a placeholder such as {version}, which the
// spec allows for the changelog and which cannot be fetched as declared.
func isTemplated(rawURL string) bool {
	return strings.ContainsAny(rawURL, "{}")
}

func DocumentationLinksResolve(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	var broken, skipped []string
	checked := 0
	for _, link := range declaredDocs(payload.Insights) {
		if isTemplated(link.URL) {
			skipped = append(skipped, fmt.Sprintf("%s (%s)", link.Field, link.URL))
			continue
		}
		checked++
		fetched, err := fetchURL(&payload, link.URL)
		if err != nil {
			broken = append(broken, fmt.Sprintf("%s (%s): %s", link.Field, link.URL, err))
		} else if fetched.StatusCode < 200 || fetched.StatusCode > 299 {
			broken = append(broken, fmt.Sprintf("%s (%s): HTTP %d", link.Field, link.URL, fetched.StatusCode))
		}
	}
	if len(broken) > 0 {
		return gemara.Failed, "Documentation links in Security Insights do not resolve: " + strings.Join(broken, "; "), gemara.High
	}
	message = fmt.Sprintf("All %d documentation links in Security Insights resolve", checked)
	if len(skipped) > 0 {
		message += "; not fetched because they contain a placeholder: " + strings.Join(skipped, ", ")
	}
	return gemara.Passed, message, gemara.High
}

type document struct {
	SourceURL   string    `json:"source_url"`
	Section     string    `json:"section,omitempty"`
	DeclaredFor []docLink `json:"declared_for,omitempty"`
	LinkedFrom  string    `json:"linked_from,omitempty"`
	Content     string    `json:"content,omitempty"`
	Truncated   bool      `json:"content_truncated,omitempty"`
	FromSection bool      `json:"content_starts_at_section,omitempty"`
	NotIncluded string    `json:"not_included,omitempty"`
}

type collection struct {
	Scope        string   `json:"scope"`
	NotRetrieved []string `json:"not_retrieved,omitempty"`
}

type documentationMaterial struct {
	Documents  []document `json:"documents"`
	Collection collection `json:"collection"`
}

const collectionScope = "Each documentation URL declared in the Security Insights file, fetched once without credentials (github.com blob URLs as raw file content). HTML is reduced to text. Links were followed one hop only from declared documents shorter than 2048 characters, at most 3 per document; those pages carry linked_from instead of declared_for. No other repository files were read. Each document's content is capped at 65536 characters and all content together at 262144 characters; content_truncated marks a document cut at its cap, and not_included marks one left out at the total cap. A section names the URL fragment the declaration points at; the content is the whole document, except that a document over its cap starts at the Markdown heading matching the section when one is found (content_starts_at_section)."

func AIReviewDocumentation(payload data.Payload) (result gemara.Result, message string, confidence gemara.ConfidenceLevel) {
	material, sources, incomplete := documentationEvidence(payload)
	return reusable_steps.AIReview(payload, "chronicler-documentation-quality", material, sources, incomplete)
}

// documentationEvidence groups declarations by URL, so a document declared for
// several fields is sent once with every topic it must cover.
func documentationEvidence(payload data.Payload) (string, []string, []string) {
	packet := documentationMaterial{Collection: collection{Scope: collectionScope}}
	index := map[string]int{}
	var sources []string
	for _, link := range declaredDocs(payload.Insights) {
		if i, ok := index[link.URL]; ok {
			packet.Documents[i].DeclaredFor = append(packet.Documents[i].DeclaredFor, link)
			continue
		}
		index[link.URL] = len(packet.Documents)
		doc := document{SourceURL: link.URL, DeclaredFor: []docLink{link}}
		if u, err := url.Parse(link.URL); err == nil {
			doc.Section = u.Fragment
		}
		packet.Documents = append(packet.Documents, doc)
		sources = append(sources, link.URL)
	}

	total := 0
	bodies := map[string]string{}
	for i := range packet.Documents {
		doc := &packet.Documents[i]
		if isTemplated(doc.SourceURL) {
			packet.Collection.NotRetrieved = append(packet.Collection.NotRetrieved, doc.SourceURL+": URL contains a placeholder")
			continue
		}
		fetched, err := fetchURL(&payload, doc.SourceURL)
		if err != nil || fetched.StatusCode < 200 || fetched.StatusCode > 299 {
			reason := fmt.Sprintf("HTTP %d", fetched.StatusCode)
			if err != nil {
				reason = err.Error()
			}
			packet.Collection.NotRetrieved = append(packet.Collection.NotRetrieved, doc.SourceURL+": "+reason)
			continue
		}
		if total >= maxMaterialChars {
			doc.NotIncluded = "total content cap reached"
			packet.Collection.NotRetrieved = append(packet.Collection.NotRetrieved, doc.SourceURL+": total content cap reached")
			continue
		}
		bodies[doc.SourceURL] = string(fetched.Body)
		text := pageText(fetched)
		limit := min(maxDocumentChars, maxMaterialChars-total)
		doc.Truncated = fetched.Truncated
		// A long document is cut at the cap, so start at the declared section
		// rather than lose it.
		if start := sectionStart(text, doc.Section); len(text) > limit && start > 0 {
			text, doc.FromSection, doc.Truncated = text[start:], true, true
		}
		if len(text) > limit {
			text, doc.Truncated = strings.ToValidUTF8(text[:limit], ""), true
		}
		doc.Content = text
		total += len(text)
	}
	// Declared documents keep the budget first; then follow short ones' links.
	for i, declared := 0, len(packet.Documents); i < declared; i++ {
		from := packet.Documents[i]
		if from.Content == "" || len(from.Content) >= maxDelegatingChars {
			continue
		}
		for _, link := range outboundLinks(from.SourceURL, bodies[from.SourceURL], index) {
			index[link] = len(packet.Documents)
			if total >= maxMaterialChars {
				packet.Collection.NotRetrieved = append(packet.Collection.NotRetrieved, link+": total content cap reached")
				continue
			}
			fetched, err := fetchURL(&payload, link)
			if err != nil || fetched.StatusCode < 200 || fetched.StatusCode > 299 {
				reason := fmt.Sprintf("HTTP %d", fetched.StatusCode)
				if err != nil {
					reason = err.Error()
				}
				packet.Collection.NotRetrieved = append(packet.Collection.NotRetrieved, link+": "+reason)
				continue
			}
			doc := document{SourceURL: link, LinkedFrom: from.SourceURL, Truncated: fetched.Truncated}
			doc.Content = pageText(fetched)
			if limit := min(maxDocumentChars, maxMaterialChars-total); len(doc.Content) > limit {
				doc.Content, doc.Truncated = strings.ToValidUTF8(doc.Content[:limit], ""), true
			}
			total += len(doc.Content)
			packet.Documents = append(packet.Documents, doc)
		}
	}
	material, _ := json.Marshal(packet) // only strings and bools: cannot fail
	incomplete := packet.Collection.NotRetrieved
	for _, doc := range packet.Documents {
		if doc.Truncated {
			incomplete = append(incomplete, doc.SourceURL+" truncated")
		}
	}
	return string(material), sources, incomplete
}

func pageText(fetched data.FetchedURL) string {
	if strings.Contains(strings.ToLower(fetched.ContentType), "html") {
		return htmlToText(string(fetched.Body))
	}
	return string(fetched.Body)
}

// pageLink matches Markdown links (group 1 is "!" for an image) and hrefs.
var pageLink = regexp.MustCompile(`(!?)\[[^\[\]\n]*\]\(\s*<?([^)\s>]+)|(?i)href\s*=\s*["']([^"']+)["']`)

// outboundLinks lists up to maxFollowedLinks https pages a document links to,
// resolved against its URL, skipping images, fragments of itself, and URLs
// already in seen.
func outboundLinks(source, body string, seen map[string]int) []string {
	base, err := url.Parse(source)
	if err != nil {
		return nil
	}
	base.Fragment = ""
	var links []string
	for _, match := range pageLink.FindAllStringSubmatch(body, -1) {
		if match[1] == "!" || len(links) == maxFollowedLinks {
			continue
		}
		ref, err := url.Parse(html.UnescapeString(match[2] + match[3]))
		if err != nil {
			continue
		}
		link := base.ResolveReference(ref)
		link.Fragment = ""
		if _, dup := seen[link.String()]; dup || link.Scheme != "https" || link.String() == base.String() || slices.Contains(links, link.String()) {
			continue
		}
		links = append(links, link.String())
	}
	return links
}

var markdownHeading = regexp.MustCompile(`(?m)^#{1,6}[ \t]+(.+?)[ \t#]*$`)

// sectionStart returns the offset of the Markdown heading whose GitHub anchor
// is section, or -1.
func sectionStart(text, section string) int {
	if section == "" {
		return -1
	}
	for _, m := range markdownHeading.FindAllStringSubmatchIndex(text, -1) {
		if headingAnchor(text[m[2]:m[3]]) == strings.ToLower(section) {
			return m[0]
		}
	}
	return -1
}

// headingAnchor approximates GitHub's heading slug: lowercase, punctuation
// dropped, spaces to hyphens.
func headingAnchor(heading string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == ' ':
			return '-'
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
			return unicode.ToLower(r)
		}
		return -1
	}, strings.TrimSpace(heading))
}

var (
	htmlSkipped    = regexp.MustCompile(`(?is)<(script|style|noscript|svg|head)\b.*?</(script|style|noscript|svg|head)\s*>`)
	htmlBreak      = regexp.MustCompile(`(?i)<(br|/p|/div|/h[1-6]|/li|/tr|/pre|/section|/article)\b[^>]*>`)
	htmlTag        = regexp.MustCompile(`(?s)<[^>]*>`)
	htmlLineBreaks = regexp.MustCompile(`\s*\n\s*`)
	htmlSpaces     = regexp.MustCompile(`[ \t\r\f\v]+`)
)

// htmlToText reduces a page to its readable text. shortcut: regexes, not a
// parser; good enough for a model to read, switch to x/net/html if markup
// leaks into the text in practice.
func htmlToText(page string) string {
	page = htmlSkipped.ReplaceAllString(page, " ")
	page = htmlBreak.ReplaceAllString(page, "\n")
	page = html.UnescapeString(htmlTag.ReplaceAllString(page, " "))
	page = htmlSpaces.ReplaceAllString(page, " ")
	return strings.TrimSpace(htmlLineBreaks.ReplaceAllString(page, "\n"))
}
