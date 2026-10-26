package data

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	pathpkg "path"
	"strings"
	"testing"

	"github.com/google/go-github/v74/github"
	"github.com/privateerproj/privateer-sdk/config"
)

// fakeGitHub serves the contents API from files (path -> content). The root
// and .github/ list their files, and paths under .github/workflows/ are also
// listed as that directory. si-tooling's discovery is pointed at it too.
func fakeGitHub(t *testing.T, files map[string]string) *github.Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, ok := strings.CutPrefix(r.URL.Path, "/repos/o/r/contents/")
		listing := path == "" || path == ".github"
		// Files are only served at the head commit, as the plugin reads them;
		// si-tooling lists the two directories without a ref.
		if ok && r.URL.Query().Get("ref") != headSHA && (!listing || r.URL.Query().Has("ref")) {
			http.Error(w, "wrong ref "+r.URL.Query().Get("ref"), http.StatusBadRequest)
			return
		}
		switch {
		case r.URL.Path == "/repos/o/r":
			_, _ = fmt.Fprint(w, `{"default_branch":"main"}`)
		case r.URL.Path == "/repos/o/r/branches/main":
			_, _ = fmt.Fprintf(w, `{"name":"main","commit":{"sha":%q}}`, headSHA)
		case ok && listing:
			var entries []string
			for name := range files {
				if dir, file := pathpkg.Split(name); strings.TrimSuffix(dir, "/") == path {
					entries = append(entries, fmt.Sprintf(`{"type":"file","name":%q,"path":%q}`, file, name))
				}
			}
			if path != "" && entries == nil {
				http.NotFound(w, r)
				return
			}
			_, _ = fmt.Fprintf(w, "[%s]", strings.Join(entries, ","))
		case ok && path == ".github/workflows":
			var entries []string
			for name := range files {
				if strings.HasPrefix(name, ".github/workflows/") {
					entries = append(entries, fmt.Sprintf(`{"type":"file","name":"x","path":%q}`, name))
				}
			}
			if entries == nil {
				http.NotFound(w, r)
				return
			}
			_, _ = fmt.Fprintf(w, "[%s]", strings.Join(entries, ","))
		case ok && files[path] != "":
			_, _ = fmt.Fprintf(w, `{"type":"file","encoding":"base64","content":%q}`,
				base64.StdEncoding.EncodeToString([]byte(files[path])))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("GITHUB_API_URL", server.URL)
	t.Setenv("GITHUB_TOKEN", "")
	client := github.NewClient(nil)
	client.BaseURL, _ = url.Parse(server.URL + "/")
	return client
}

const headSHA = "0123456789abcdef0123456789abcdef01234567"

const validInsights = "header:\n  schema-version: 2.2.0\n  url: https://example.com/o/r\n"

func loadFake(t *testing.T, files map[string]string) *Payload {
	t.Helper()
	p := &Payload{Owner: "o", Repo: "r", ghClient: fakeGitHub(t, files), cache: &payloadCache{}}
	if err := p.load(); err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

func TestLoadFindsMisnamedInsights(t *testing.T) {
	p := loadFake(t, map[string]string{"SECURITY-INSIGHTS.yml": validInsights, "README.md": "hi"})
	if p.DefaultBranch != "main" || p.InsightsPath != "SECURITY-INSIGHTS.yml" || p.InsightsError != nil {
		t.Fatalf("got branch %q path %q err %v", p.DefaultBranch, p.InsightsPath, p.InsightsError)
	}
	if p.Insights.Header.URL.String() != "https://example.com/o/r" || string(p.InsightsRaw) != validInsights {
		t.Fatalf("insights not loaded: %+v", p.Insights.Header)
	}
}

func TestLoadInsightsParseError(t *testing.T) {
	p := loadFake(t, map[string]string{"security-insights.yml": "not: [valid"})
	if p.InsightsError == nil || p.InsightsRaw == nil {
		t.Fatalf("want parse error with raw bytes kept, got err %v", p.InsightsError)
	}
	// nested pointers are initialized even when parsing failed
	_ = p.Insights.Project.VulnerabilityReporting.Contact.Email
	_ = p.Insights.Repository.ReleaseDetails
}

// si-tooling's discovery decides where the file is: the spec's names at the
// root or in .github/, .yml before .yaml, the root before .github/.
func TestLoadDiscoversInsights(t *testing.T) {
	for _, tc := range []struct {
		name  string
		files map[string]string
		want  string
	}{
		{"root yml", map[string]string{"security-insights.yml": validInsights}, "security-insights.yml"},
		{"root yaml", map[string]string{"security-insights.yaml": validInsights}, "security-insights.yaml"},
		{".github", map[string]string{".github/security-insights.yml": validInsights}, ".github/security-insights.yml"},
		{"both extensions", map[string]string{"security-insights.yaml": validInsights, "security-insights.yml": validInsights}, "security-insights.yml"},
		{"root before .github", map[string]string{".github/security-insights.yml": validInsights, "security-insights.yaml": validInsights}, "security-insights.yaml"},
		{"none", map[string]string{"README.md": "hi"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := loadFake(t, tc.files)
			if p.InsightsPath != tc.want || p.InsightsError != nil {
				t.Fatalf("got path %q err %v, want %q", p.InsightsPath, p.InsightsError, tc.want)
			}
			if tc.want != "" && string(p.InsightsRaw) != validInsights {
				t.Fatalf("raw = %q", p.InsightsRaw)
			}
		})
	}
	p := loadFake(t, map[string]string{".github/security-insights.yml": validInsights, "README.md": "hi"})
	if strings.Join(p.GitHubDirEntries, ",") != "security-insights.yml" || strings.Join(p.RootEntries, ",") != "README.md" {
		t.Fatalf("entries: root %v .github %v", p.RootEntries, p.GitHubDirEntries)
	}
}

func TestGetWorkflowFiles(t *testing.T) {
	p := loadFake(t, map[string]string{".github/workflows/ci.yml": "on: push"})
	files, err := p.GetWorkflowFiles()
	if err != nil || len(files) != 1 || string(files[0].Content) != "on: push" {
		t.Fatalf("got %+v, %v", files, err)
	}

	p = loadFake(t, map[string]string{"README.md": "hi"})
	if files, err := p.GetWorkflowFiles(); err != nil || files != nil {
		t.Fatalf("missing dir: got %+v, %v", files, err)
	}
}

func TestRawGitHubURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://github.com/o/r/blob/main/docs/SECURITY.md#L3": "https://raw.githubusercontent.com/o/r/main/docs/SECURITY.md",
		"https://github.com/o/r/tree/main/docs":                "https://github.com/o/r/tree/main/docs",
		"https://example.com/o/r/blob/main/x":                  "https://example.com/o/r/blob/main/x",
	} {
		u, _ := url.Parse(in)
		if got := rawGitHubURL(u); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

func TestFetchURL(t *testing.T) {
	big := strings.Repeat("a", MaxFetchedBodyBytes+10)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("credentials sent to %s", r.URL)
		}
		switch r.URL.Path {
		case "/big":
			_, _ = fmt.Fprint(w, big)
		case "/moved":
			http.Redirect(w, r, "/big", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	p := &Payload{plainClient: server.Client()}

	got, err := p.FetchURL(server.URL + "/moved")
	if err != nil || !got.Truncated || len(got.Body) != MaxFetchedBodyBytes || got.FinalURL != server.URL+"/big" {
		t.Fatalf("truncation/redirect: %v truncated=%v len=%d final=%s", err, got.Truncated, len(got.Body), got.FinalURL)
	}
	if got, err := p.FetchURL(server.URL + "/missing"); err != nil || got.StatusCode != http.StatusNotFound {
		t.Fatalf("non-2xx should not error: %v %d", err, got.StatusCode)
	}
	if _, err := p.FetchURL("http://example.com/x"); err == nil {
		t.Fatal("http URL should be rejected")
	}
}

// The real Loader wiring must keep the GitHub token off non-GitHub hosts.
func TestTokenNotSentToGrcStore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Errorf("token sent to grc.store: %s", r.Header.Get("Authorization"))
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	p := newPayload(&config.Config{Vars: map[string]any{"token": "secret", "grc_store_url": server.URL}})
	if target, err := p.GetGrcStoreTarget("ns", "id"); target != nil || err != nil {
		t.Fatalf("404 should be (nil, nil), got %v, %v", target, err)
	}
}

func TestGrcStore(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.RequestURI() {
		case "/v1/targets/ns/a%2Fb/evaluations?limit=2":
			_, _ = fmt.Fprint(w, `{"items":[{"log_version":"v2","result":"Passed","counts":{"passed":3}}]}`)
		case "/v1/catalogs/ns/log/versions/v2":
			_, _ = fmt.Fprint(w, `{"log":true}`)
		default:
			w.WriteHeader(http.StatusBadGateway)
			_, _ = fmt.Fprint(w, `{"error":"upstream","detail":"down"}`)
		}
	}))
	defer server.Close()
	p := &Payload{grcStoreURL: server.URL}

	evals, err := p.GetGrcStoreEvaluations("ns", "a/b", 2)
	if err != nil || len(evals) != 1 || evals[0].LogVersion != "v2" || evals[0].Counts.Passed != 3 {
		t.Fatalf("evaluations: %+v, %v", evals, err)
	}
	if raw, err := p.GetGrcStoreLog("ns", "log", "v2"); err != nil || string(raw) != `{"log":true}` {
		t.Fatalf("log: %s, %v", raw, err)
	}
	if _, err := p.GetGrcStoreTarget("ns", "x"); err == nil || !strings.Contains(err.Error(), "down") {
		t.Fatalf("want hub error detail, got %v", err)
	}
}

func TestValidateMaturityLevel(t *testing.T) {
	tests := []struct {
		name          string
		applicability []string
		level         any
		wantErr       bool
	}{
		{"chronicler without level", []string{"cleaner", "chronicler"}, nil, true},
		{"defender with empty string", []string{"defender"}, "", true},
		{"out of range", []string{"defender"}, 4, true},
		{"numeric string", []string{"chronicler"}, "2", false},
		{"int", []string{"defender"}, 3, false},
		{"not needed by these badges", []string{"cleaner", "mechanizer"}, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &config.Config{Policy: config.Policy{Applicability: tt.applicability}, Vars: map[string]any{}}
			if tt.level != nil {
				c.Vars["maturity_level"] = tt.level
			}
			if err := validateMaturityLevel(c); (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoadPinsHeadCommit(t *testing.T) {
	p := loadFake(t, map[string]string{"security-insights.yml": validInsights})
	if p.Commit != headSHA {
		t.Fatalf("Commit = %q, want %q", p.Commit, headSHA)
	}
	tests := map[string]string{
		"https://github.com/o/r/blob/main/SECURITY.md#x": "https://github.com/o/r/blob/" + headSHA + "/SECURITY.md#x",
		"https://github.com/O/R/blob/main/docs/a.md":     "https://github.com/o/r/blob/" + headSHA + "/docs/a.md",
		"https://github.com/o/r/blob/v1.0/SECURITY.md":   "https://github.com/o/r/blob/v1.0/SECURITY.md",
		"https://github.com/other/r/blob/main/x.md":      "https://github.com/other/r/blob/main/x.md",
		"https://example.com/o/r/blob/main/x.md":         "https://example.com/o/r/blob/main/x.md",
	}
	for in, want := range tests {
		if got := p.pinned(in); got != want {
			t.Errorf("pinned(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidateTarget(t *testing.T) {
	for name, vars := range map[string]map[string]any{
		"owner missing": {"repo": "r"},
		"repo empty":    {"owner": "o", "repo": " "},
	} {
		c := &config.Config{Vars: vars}
		if err := validateTarget(c); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if err := validateTarget(&config.Config{Vars: map[string]any{"owner": "o", "repo": "r"}}); err != nil {
		t.Errorf("owner and repo set: %v", err)
	}
}
