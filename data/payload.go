package data

import (
	"errors"
	"net/http"

	"github.com/gemaraproj/go-gemara"
	"github.com/google/go-github/v74/github"
	"github.com/ossf/si-tooling/v2/si"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/privateerproj/privateer-sdk/pluginkit"
)

// DefaultGrcStoreURL is the public grc.store hub API. Override it with the
// optional grc_store_url var (e.g. a preview hub).
const DefaultGrcStoreURL = "https://hub.grc.store"

var errNotImplemented = errors.New("not implemented")

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
	// RootEntries are the names of the files and directories at the root of
	// the default branch, with their original case.
	RootEntries []string

	// Insights is the parsed Security Insights file. InsightsPath is where it
	// was found ("" when there is none); InsightsRaw is its exact bytes.
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

// MaxFetchedBodyBytes caps how much of a fetched document is kept.
const MaxFetchedBodyBytes = 256 * 1024

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
	Signer            struct {
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

// Loader builds the Payload: repository metadata, root listing, and the
// Security Insights file. Everything else is fetched lazily by the methods.
func Loader(config *config.Config) (payload any, err error) {
	return nil, errNotImplemented
}

// GetFileContent returns a repository file's bytes from the default branch.
func (p *Payload) GetFileContent(path string) ([]byte, error) {
	return nil, errNotImplemented
}

// GetWorkflowFiles returns every file under .github/workflows on the default
// branch.
func (p *Payload) GetWorkflowFiles() ([]WorkflowFile, error) {
	return nil, errNotImplemented
}

// FetchURL fetches an https URL declared in Security Insights, without GitHub
// credentials. github.com blob URLs are fetched as their raw content.
func (p *Payload) FetchURL(url string) (FetchedURL, error) {
	return FetchedURL{}, errNotImplemented
}

// GetGrcStoreTarget returns the grc.store target, or (nil, nil) when the hub
// reports it does not exist.
func (p *Payload) GetGrcStoreTarget(namespace, id string) (*GrcStoreTarget, error) {
	return nil, errNotImplemented
}

// GetGrcStoreEvaluations returns up to limit of the target's most recent
// evaluations, newest first.
func (p *Payload) GetGrcStoreEvaluations(namespace, id string, limit int) ([]GrcStoreEvaluation, error) {
	return nil, errNotImplemented
}

// GetGrcStoreLog returns a published evaluation log version as raw JSON.
func (p *Payload) GetGrcStoreLog(namespace, id, version string) ([]byte, error) {
	return nil, errNotImplemented
}
