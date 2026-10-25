package data

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// GetGrcStoreTarget returns the grc.store target, or (nil, nil) when the hub
// reports it does not exist.
func (p *Payload) GetGrcStoreTarget(namespace, id string) (*GrcStoreTarget, error) {
	path := "/v1/targets/" + url.PathEscape(namespace) + "/" + url.PathEscape(id)
	body, err := p.grcStoreGet(path)
	if err != nil || body == nil {
		return nil, err
	}
	var target GrcStoreTarget
	if err := json.Unmarshal(body, &target); err != nil {
		return nil, fmt.Errorf("failed to decode grc.store target %s: %w", path, err)
	}
	return &target, nil
}

// GetGrcStoreEvaluations returns up to limit of the target's most recent
// evaluations, newest first.
func (p *Payload) GetGrcStoreEvaluations(namespace, id string, limit int) ([]GrcStoreEvaluation, error) {
	path := fmt.Sprintf("/v1/targets/%s/%s/evaluations?limit=%d", url.PathEscape(namespace), url.PathEscape(id), limit)
	body, err := p.grcStoreGet(path)
	if err != nil {
		return nil, err
	}
	if body == nil {
		return nil, fmt.Errorf("grc.store %s: not found", path)
	}
	var page struct {
		Items []GrcStoreEvaluation `json:"items"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, fmt.Errorf("failed to decode grc.store evaluations %s: %w", path, err)
	}
	return page.Items, nil
}

// GetGrcStoreLog returns a published evaluation log version as raw JSON.
func (p *Payload) GetGrcStoreLog(namespace, id, version string) ([]byte, error) {
	path := "/v1/catalogs/" + url.PathEscape(namespace) + "/" + url.PathEscape(id) + "/versions/" + url.PathEscape(version)
	body, err := p.grcStoreGet(path)
	if err == nil && body == nil {
		err = fmt.Errorf("grc.store %s: not found", path)
	}
	return body, err
}

// grcStoreGet does an unauthenticated GET against the hub, cached by path.
// A 404 returns (nil, nil) so each caller decides what absence means.
func (p *Payload) grcStoreGet(path string) ([]byte, error) {
	if p.cache != nil {
		if entry, ok := p.cache.grcStore[path]; ok {
			body, _ := entry.value.([]byte)
			return body, entry.err
		}
	}
	body, err := p.fetchGrcStore(path)
	if p.cache != nil {
		if p.cache.grcStore == nil {
			p.cache.grcStore = make(map[string]grcStoreCacheEntry)
		}
		p.cache.grcStore[path] = grcStoreCacheEntry{value: body, err: err}
	}
	return body, err
}

func (p *Payload) fetchGrcStore(path string) ([]byte, error) {
	base := p.grcStoreURL
	if base == "" {
		base = DefaultGrcStoreURL
	}
	request, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	response, err := p.plain().Do(request)
	if err != nil {
		return nil, fmt.Errorf("grc.store request %s failed: %w", path, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read grc.store response %s: %w", path, err)
	}
	switch {
	case response.StatusCode == http.StatusNotFound:
		return nil, nil
	case response.StatusCode < 200 || response.StatusCode > 299:
		var hubErr struct {
			Error  string `json:"error"`
			Detail string `json:"detail"`
		}
		if json.Unmarshal(body, &hubErr) == nil && hubErr.Error != "" {
			return nil, fmt.Errorf("grc.store %s: %s: %s (%s)", path, response.Status, hubErr.Error, hubErr.Detail)
		}
		return nil, fmt.Errorf("grc.store %s: %s", path, response.Status)
	}
	return body, nil
}
