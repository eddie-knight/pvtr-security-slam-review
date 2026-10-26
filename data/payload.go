package data

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	pathpkg "path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gemaraproj/go-gemara"
	"github.com/google/go-github/v74/github"
	"github.com/hashicorp/go-hclog"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/privateerproj/privateer-sdk/pluginkit"
	"golang.org/x/oauth2"
)

// DefaultGrcStoreURL is the public grc.store hub API. Override it with the
// optional grc_store_url var (e.g. a preview hub).
const DefaultGrcStoreURL = "https://hub.grc.store"

// Payload is everything a step may read. The Loader fills the eager fields;
// the methods fetch lazily and cache in the shared payloadCache, because steps
// receive the Payload by value (see evaluation_plans.TypedStep).
type Payload struct {
	*pluginkit.APICallCounter // Enable Privateer benchmarking for API calls
	Evidence                  *gemara.EvidenceCollector
	Config                    *config.Config

	Owner         string
	Repo          string
	DefaultBranch string
	// Commit is the default branch's head when the run started. Repository
	// files are read at it, so every step sees the same tree.
	Commit string
	// RootEntries and GitHubDirEntries are the names of the files and
	// directories at the root and in .github/ of the default branch, with
	// their original case: the two places a Security Insights file may live.
	RootEntries      []string
	GitHubDirEntries []string

	// Insights is the parsed Security Insights file. InsightsPath is where
	// si-tooling's discovery found it ("" when there is none); InsightsRaw is
	// its exact bytes.
	// InsightsError is set when the file exists but si-tooling rejected it.
	Insights      si.SecurityInsights
	InsightsPath  string
	InsightsRaw   []byte
	InsightsError error

	ghClient    *github.Client
	httpClient  *http.Client // authenticated to GitHub; never send it elsewhere
	plainClient *http.Client // unauthenticated, for external URLs and grc.store
	grcStoreURL string
	cache       *payloadCache
}

// payloadCache holds lazily-fetched data shared by every step. Deliberately
// unsynchronized: the SDK runs steps one at a time.
type payloadCache struct {
	files      map[string]fileCacheEntry
	workflows  []WorkflowFile
	workflowsE error
	workflowsL bool
	urls       map[string]urlCacheEntry
	grcStore   map[string]grcStoreCacheEntry
}

type fileCacheEntry struct {
	content []byte
	err     error
}

type urlCacheEntry struct {
	fetched FetchedURL
	err     error
}

type grcStoreCacheEntry struct {
	value any
	err   error
}

// WorkflowFile is one file under .github/workflows on the default branch.
type WorkflowFile struct {
	Path    string
	Content []byte
}

// WorkflowRun is one run of a workflow, as the Actions API lists it.
type WorkflowRun struct {
	Event      string
	Status     string
	Conclusion string
	CreatedAt  time.Time
	URL        string
}

// FetchedURL is the outcome of fetching a URL declared in Security Insights.
// A non-2xx response is not an error: StatusCode records it so steps can
// report "does not resolve" as a finding rather than a scanner failure.
type FetchedURL struct {
	URL         string // as declared
	FinalURL    string // after redirects
	StatusCode  int
	ContentType string
	Body        []byte // capped at MaxFetchedBodyBytes
	Truncated   bool
}

// MaxFetchedBodyBytes caps how much of a fetched document is kept. Docs-site
// pages run past 256 KB of HTML (Meshery) and GitHub release pages past 512 KB.
const MaxFetchedBodyBytes = 1024 * 1024

// GrcStoreTarget is GET /v1/targets/{namespace}/{id}.
type GrcStoreTarget struct {
	Namespace          string                  `json:"namespace"`
	TargetID           string                  `json:"target_id"`
	Name               string                  `json:"name"`
	Type               string                  `json:"type"`
	URI                string                  `json:"uri"`
	VerificationMethod string                  `json:"verification_method"`
	VerifiedAt         string                  `json:"verified_at"`
	Versions           []GrcStoreTargetVersion `json:"versions"`
	CreatedAt          string                  `json:"created_at"`
	UpdatedAt          string                  `json:"updated_at"`
}

type GrcStoreTargetVersion struct {
	TargetVersion   string             `json:"target_version"`
	Latest          GrcStoreEvaluation `json:"latest"`
	EvaluationCount int                `json:"evaluation_count"`
}

// GrcStoreEvaluation is one published evaluation run: an item of
// GET /v1/targets/{namespace}/{id}/evaluations, and a target version's latest.
type GrcStoreEvaluation struct {
	LogNamespace      string `json:"log_namespace"`
	LogID             string `json:"log_id"`
	LogVersion        string `json:"log_version"`
	LogManifestDigest string `json:"log_manifest_digest"`
	TargetVersion     string `json:"target_version"`
	RunAt             string `json:"run_at"`
	CatalogRefID      string `json:"catalog_ref_id"`
	CatalogNamespace  string `json:"catalog_namespace"`
	CatalogID         string `json:"catalog_id"`
	EvaluatorID       string `json:"evaluator_id"`
	EvaluatorName     string `json:"evaluator_name"`
	EvaluatorPlugin   struct {
		Version string `json:"version"`
	} `json:"evaluator_plugin"`
	Signer struct {
		WorkflowRef      string `json:"workflow_ref"`
		WorkflowDigest   string `json:"workflow_digest"`
		CallerRepository string `json:"caller_repository"`
		RunURI           string `json:"run_uri"`
	} `json:"signer"`
	Result string `json:"result"`
	Counts struct {
		Passed        int `json:"passed"`
		Failed        int `json:"failed"`
		NeedsReview   int `json:"needs_review"`
		NotRun        int `json:"not_run"`
		NotApplicable int `json:"not_applicable"`
		Unknown       int `json:"unknown"`
	} `json:"counts"`
	EvaluatedRequirements int `json:"evaluated_requirements"`
	TotalRequirements     int `json:"total_requirements"`
}

// AddEvidence, GetEvidence, and ClearEvidence implement gemara.HasEvidence.
// Nil-safe: a payload without a collector silently drops evidence.
func (p Payload) AddEvidence(evidence gemara.Evidence) {
	if p.Evidence != nil {
		p.Evidence.AddEvidence(evidence)
	}
}

func (p Payload) GetEvidence() []gemara.Evidence {
	if p.Evidence == nil {
		return nil
	}
	return p.Evidence.GetEvidence()
}

func (p Payload) ClearEvidence() {
	if p.Evidence != nil {
		p.Evidence.ClearEvidence()
	}
}

// discoverInsights is si-tooling's lookup of the Security Insights file; a
// test hook.
var discoverInsights = si.Discover

// Loader builds the Payload: repository metadata, root listing, and the
// Security Insights file. Everything else is fetched lazily by the methods.
// A target that cannot load is logged as an error, so its log never reads as
// a clean run.
func Loader(config *config.Config) (payload any, err error) {
	p := newPayload(config)
	err = validateTarget(config)
	if err == nil {
		err = p.load()
	}
	if err != nil {
		p.logger().Error("target not evaluated: " + err.Error())
		return nil, err
	}
	p.logger().Info(fmt.Sprintf("evaluating %s/%s at %s@%s", p.Owner, p.Repo, p.DefaultBranch, p.Commit))
	return any(*p), nil
}

// validateTarget fails the target before any request when its vars cannot
// describe a repository to review.
func validateTarget(c *config.Config) error {
	for _, name := range []string{"owner", "repo"} {
		if strings.TrimSpace(c.GetString(name)) == "" {
			return fmt.Errorf("%s is empty", name)
		}
	}
	return validateMaturityLevel(c)
}

// maturityBadges are the badges whose checks depend on maturity_level.
var maturityBadges = []string{"chronicler", "defender"}

// validateMaturityLevel fails the target before any request when a badge
// that needs maturity_level is applicable and the var is missing or not 1-3:
// a guessed level would judge the project against the wrong controls.
func validateMaturityLevel(c *config.Config) error {
	if !slices.ContainsFunc(c.Policy.Applicability, func(a string) bool { return slices.Contains(maturityBadges, a) }) {
		return nil
	}
	if _, ok := MaturityLevel(c); !ok {
		got := "it is missing"
		if value, _ := c.GetVar("maturity_level"); value != nil {
			got = fmt.Sprintf("got %q", fmt.Sprint(value))
		}
		return fmt.Errorf("maturity_level must be 1, 2, or 3 when chronicler or defender is applicable; %s", got)
	}
	return nil
}

// MaturityLevel reads the maturity_level var as an int or a numeric string.
func MaturityLevel(c *config.Config) (int, bool) {
	if c == nil {
		return 0, false
	}
	value, _ := c.GetVar("maturity_level")
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

// newPayload wires the clients without touching the network.
func newPayload(config *config.Config) *Payload {
	// Count every request either client makes through this transport
	callCounter := &pluginkit.APICallCounter{}
	httpClient := callCounter.WrapClient(oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: config.GetString("token")},
	)))
	grcStoreURL := strings.TrimSuffix(config.GetString("grc_store_url"), "/")
	if grcStoreURL == "" {
		grcStoreURL = DefaultGrcStoreURL
	}
	return &Payload{
		APICallCounter: callCounter,
		Evidence:       &gemara.EvidenceCollector{},
		Config:         config,
		Owner:          config.GetString("owner"),
		Repo:           config.GetString("repo"),
		ghClient:       github.NewClient(httpClient),
		httpClient:     httpClient,
		plainClient:    callCounter.WrapClient(newPlainClient()),
		grcStoreURL:    grcStoreURL,
		cache:          &payloadCache{},
	}
}

// load reads the eager fields. Only failing to read the repository itself is
// an error; a missing or broken Security Insights file is a finding for steps.
func (p *Payload) load() error {
	ctx := context.Background()
	repo, _, err := p.ghClient.Repositories.Get(ctx, p.Owner, p.Repo)
	if err != nil {
		return fmt.Errorf("failed to read repository %s/%s: %w", p.Owner, p.Repo, err)
	}
	p.DefaultBranch = repo.GetDefaultBranch()
	// An empty repository has no branch head either
	branch, _, err := p.ghClient.Repositories.GetBranch(ctx, p.Owner, p.Repo, p.DefaultBranch, 1)
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("failed to read the head of %s/%s@%s: %w", p.Owner, p.Repo, p.DefaultBranch, err)
	}
	p.Commit = branch.GetCommit().GetSHA()

	_, root, _, err := p.ghClient.Repositories.GetContents(ctx, p.Owner, p.Repo, "",
		&github.RepositoryContentGetOptions{Ref: p.ref()})
	// An empty repository has no root listing: GitHub answers 404
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("failed to list repository root: %w", err)
	}
	for _, entry := range root {
		p.RootEntries = append(p.RootEntries, entry.GetName())
	}
	_, dotGitHub, _, err := p.ghClient.Repositories.GetContents(ctx, p.Owner, p.Repo, ".github",
		&github.RepositoryContentGetOptions{Ref: p.ref()})
	if err != nil && !isNotFound(err) {
		return fmt.Errorf("failed to list .github: %w", err)
	}
	for _, entry := range dotGitHub {
		p.GitHubDirEntries = append(p.GitHubDirEntries, entry.GetName())
	}

	return p.loadSecurityInsights(ctx)
}

// loadSecurityInsights finds the file with si-tooling, which reads only
// GITHUB_TOKEN from the environment, so the run's token is lent to it.
// shortcut: si.Discover reads the default branch, not p.Commit; the file is then read at p.Commit, so a push between the two can only surface as a read error.
func (p *Payload) loadSecurityInsights(ctx context.Context) error {
	if p.Config != nil && p.Config.GetString("token") != "" && os.Getenv("GITHUB_TOKEN") == "" {
		token := p.Config.GetString("token")
		if err := os.Setenv("GITHUB_TOKEN", token); err != nil {
			return err
		}
	}
	path, err := discoverInsights(ctx, p.Owner, p.Repo)
	if err != nil && !errors.Is(err, si.ErrNotFound) {
		return fmt.Errorf("failed to look for the Security Insights file: %w", err)
	}
	p.InsightsPath = path
	if p.InsightsPath != "" {
		raw, err := p.GetFileContent(p.InsightsPath)
		if err == nil {
			p.InsightsRaw = raw
			var insights *si.SecurityInsights
			if insights, err = si.Load(raw); err == nil {
				p.Insights = *insights
			}
		}
		if err != nil {
			p.InsightsError = fmt.Errorf("failed to read security insights file %s: %w", p.InsightsPath, err)
			p.logger().Error(p.InsightsError.Error())
		}
	}
	p.ensureInsightsInitialized()
	return nil
}

// ensureInsightsInitialized fills nil pointers so steps can read nested
// fields without nil checks.
func (p *Payload) ensureInsightsInitialized() {
	if p.Insights.Repository == nil {
		p.Insights.Repository = &si.Repository{}
	}
	if p.Insights.Project == nil {
		p.Insights.Project = &si.Project{}
	}
	if p.Insights.Repository.Documentation == nil {
		p.Insights.Repository.Documentation = &si.RepositoryDocumentation{}
	}
	if p.Insights.Repository.ReleaseDetails == nil {
		p.Insights.Repository.ReleaseDetails = &si.ReleaseDetails{}
	}
	if p.Insights.Project.Documentation == nil {
		p.Insights.Project.Documentation = &si.ProjectDocumentation{}
	}
	if p.Insights.Project.VulnerabilityReporting.Contact == nil {
		p.Insights.Project.VulnerabilityReporting.Contact = &si.Contact{}
	}
}

// ref is the commit repository files are read at.
func (p *Payload) ref() string {
	if p.Commit != "" {
		return p.Commit
	}
	return p.DefaultBranch
}

func (p *Payload) logger() hclog.Logger {
	if p.Config == nil || p.Config.Logger == nil {
		return hclog.NewNullLogger()
	}
	return p.Config.Logger
}

func isNotFound(err error) bool {
	var ghErr *github.ErrorResponse
	return errors.As(err, &ghErr) && ghErr.Response != nil && ghErr.Response.StatusCode == http.StatusNotFound
}

// GetFileContent returns a repository file's bytes at Commit.
// Errors are cached too: a file that just failed fails the same way for every
// step. A payload without a cache (as built directly in tests) calls through.
func (p *Payload) GetFileContent(path string) ([]byte, error) {
	if p.cache != nil {
		if entry, ok := p.cache.files[path]; ok {
			return entry.content, entry.err
		}
	}
	content, err := p.fetchFileContent(path)
	if p.cache != nil {
		if p.cache.files == nil {
			p.cache.files = make(map[string]fileCacheEntry)
		}
		p.cache.files[path] = fileCacheEntry{content: content, err: err}
	}
	return content, err
}

// shortcut: the contents API inlines files up to 1MB only; larger files error,
// fetch download_url if a step ever needs one.
func (p *Payload) fetchFileContent(path string) ([]byte, error) {
	if p.ghClient == nil {
		return nil, fmt.Errorf("payload missing GitHub client")
	}
	file, _, _, err := p.ghClient.Repositories.GetContents(context.Background(), p.Owner, p.Repo, path,
		&github.RepositoryContentGetOptions{Ref: p.ref()})
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve file content for %s: %w", path, err)
	}
	if file == nil {
		return nil, fmt.Errorf("%s is a directory, not a file", path)
	}
	content, err := file.GetContent()
	if err != nil {
		return nil, fmt.Errorf("failed to decode file content for %s: %w", path, err)
	}
	return []byte(content), nil
}

// GetWorkflowFiles returns every file under .github/workflows on the default
// branch. A repository without the directory has no workflows, not an error.
func (p *Payload) GetWorkflowFiles() ([]WorkflowFile, error) {
	if p.cache != nil && p.cache.workflowsL {
		return p.cache.workflows, p.cache.workflowsE
	}
	files, err := p.fetchWorkflowFiles()
	if p.cache != nil {
		p.cache.workflows, p.cache.workflowsE, p.cache.workflowsL = files, err, true
	}
	return files, err
}

func (p *Payload) fetchWorkflowFiles() ([]WorkflowFile, error) {
	if p.ghClient == nil {
		return nil, fmt.Errorf("payload missing GitHub client")
	}
	const dir = ".github/workflows"
	_, entries, _, err := p.ghClient.Repositories.GetContents(context.Background(), p.Owner, p.Repo, dir,
		&github.RepositoryContentGetOptions{Ref: p.ref()})
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to list %s: %w", dir, err)
	}
	var files []WorkflowFile
	for _, entry := range entries {
		if entry.GetType() != "file" {
			continue
		}
		content, err := p.GetFileContent(entry.GetPath())
		if err != nil {
			return nil, err
		}
		files = append(files, WorkflowFile{Path: entry.GetPath(), Content: content})
	}
	return files, nil
}

// GetWorkflowRuns returns the most recent runs of the workflow at path on the
// default branch, newest first.
func (p *Payload) GetWorkflowRuns(path string) ([]WorkflowRun, error) {
	if p.ghClient == nil {
		return nil, fmt.Errorf("payload missing GitHub client")
	}
	list, _, err := p.ghClient.Actions.ListWorkflowRunsByFileName(context.Background(), p.Owner, p.Repo, pathpkg.Base(path),
		&github.ListWorkflowRunsOptions{Branch: p.DefaultBranch, ListOptions: github.ListOptions{PerPage: 20}})
	if err != nil {
		return nil, fmt.Errorf("failed to list runs of %s: %w", path, err)
	}
	var runs []WorkflowRun
	for _, run := range list.WorkflowRuns {
		runs = append(runs, WorkflowRun{
			Event:      run.GetEvent(),
			Status:     run.GetStatus(),
			Conclusion: run.GetConclusion(),
			CreatedAt:  run.GetCreatedAt().Time,
			URL:        run.GetHTMLURL(),
		})
	}
	return runs, nil
}

// PrivateReportingEnabled reports whether GitHub private vulnerability
// reporting is switched on for owner/repo, which may be another repository
// such as the organization's .github.
func (p *Payload) PrivateReportingEnabled(owner, repo string) (bool, error) {
	if p.ghClient == nil {
		return false, fmt.Errorf("payload missing GitHub client")
	}
	enabled, _, err := p.ghClient.Repositories.IsPrivateReportingEnabled(context.Background(), owner, repo)
	return enabled, err
}
