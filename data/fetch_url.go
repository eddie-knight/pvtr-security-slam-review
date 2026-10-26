package data

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// newPlainClient builds the unauthenticated client for everything outside the
// GitHub API. Redirects may not downgrade to plain http.
func newPlainClient() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			if req.URL.Scheme != "https" && via[0].URL.Scheme == "https" {
				return fmt.Errorf("refusing redirect to non-https URL %s", req.URL)
			}
			return nil
		},
	}
}

// plain returns plainClient, or a fresh one for a payload built directly in
// tests. Never falls back to httpClient: it carries the GitHub token.
func (p *Payload) plain() *http.Client {
	if p.plainClient != nil {
		return p.plainClient
	}
	return newPlainClient()
}

// FetchURL fetches an https URL declared in Security Insights, without GitHub
// credentials. github.com blob URLs are fetched as their raw content, and
// those on this repository's default branch at Commit.
func (p *Payload) FetchURL(rawURL string) (FetchedURL, error) {
	if p.cache != nil {
		if entry, ok := p.cache.urls[rawURL]; ok {
			return entry.fetched, entry.err
		}
	}
	fetched, err := fetchURL(p.plain(), p.pinned(rawURL))
	fetched.URL = rawURL
	if p.cache != nil {
		if p.cache.urls == nil {
			p.cache.urls = make(map[string]urlCacheEntry)
		}
		p.cache.urls[rawURL] = urlCacheEntry{fetched: fetched, err: err}
	}
	return fetched, err
}

func fetchURL(client *http.Client, declared string) (FetchedURL, error) {
	fetched := FetchedURL{URL: declared}
	u, err := url.Parse(declared)
	if err != nil {
		return fetched, fmt.Errorf("invalid URL %q: %w", declared, err)
	}
	if u.Scheme != "https" {
		return fetched, fmt.Errorf("refusing to fetch %q: only https URLs are fetched", declared)
	}
	response, err := client.Get(rawGitHubURL(u))
	if err != nil {
		return fetched, fmt.Errorf("failed to fetch %s: %w", declared, err)
	}
	defer func() { _ = response.Body.Close() }()

	fetched.FinalURL = response.Request.URL.String()
	fetched.StatusCode = response.StatusCode
	fetched.ContentType = response.Header.Get("Content-Type")
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxFetchedBodyBytes+1))
	if err != nil {
		return fetched, fmt.Errorf("failed to read %s: %w", declared, err)
	}
	if len(body) > MaxFetchedBodyBytes {
		body, fetched.Truncated = body[:MaxFetchedBodyBytes], true
	}
	fetched.Body = body
	return fetched, nil
}

// pinned rewrites a github.com blob URL on this repository's default branch to
// the same file at Commit; any other URL is returned unchanged.
func (p *Payload) pinned(rawURL string) string {
	if p.Commit == "" {
		return rawURL
	}
	prefix := fmt.Sprintf("https://github.com/%s/%s/blob/%s/", p.Owner, p.Repo, p.DefaultBranch)
	if len(rawURL) > len(prefix) && strings.EqualFold(rawURL[:len(prefix)], prefix) {
		return fmt.Sprintf("https://github.com/%s/%s/blob/%s/", p.Owner, p.Repo, p.Commit) + rawURL[len(prefix):]
	}
	return rawURL
}

// rawGitHubURL rewrites https://github.com/{o}/{r}/blob/{ref}/{path} to its
// raw.githubusercontent.com equivalent, dropping any query or fragment (e.g.
// #L10). Any other URL is returned unchanged.
func rawGitHubURL(u *url.URL) string {
	if strings.EqualFold(u.Host, "github.com") {
		parts := strings.SplitN(u.EscapedPath(), "/", 6) // "", o, r, "blob", ref, path
		if len(parts) == 6 && parts[3] == "blob" && parts[5] != "" {
			return "https://raw.githubusercontent.com/" + strings.Join([]string{parts[1], parts[2], parts[4], parts[5]}, "/")
		}
	}
	return u.String()
}
