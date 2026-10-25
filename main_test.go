package main

import (
	"os"
	"sort"
	"testing"

	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans"
	"github.com/goccy/go-yaml"
)

// The catalog and the step map are bound only by requirement ID strings; a
// typo in either silently skips a badge. Pin both directions.
func TestCatalogMatchesSteps(t *testing.T) {
	if _, err := newOrchestrator(); err != nil {
		t.Fatalf("newOrchestrator: %v", err)
	}
	raw, err := os.ReadFile("data/catalogs/Security_Slam_Fall_2026.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var catalog struct {
		Controls []struct {
			Requirements []struct {
				ID string `yaml:"id"`
			} `yaml:"assessment-requirements"`
		} `yaml:"controls"`
	}
	if err := yaml.Unmarshal(raw, &catalog); err != nil {
		t.Fatal(err)
	}
	var inCatalog, inSteps []string
	for _, c := range catalog.Controls {
		for _, r := range c.Requirements {
			inCatalog = append(inCatalog, r.ID)
		}
	}
	for id := range evaluation_plans.AllSteps() {
		inSteps = append(inSteps, id)
	}
	sort.Strings(inCatalog)
	sort.Strings(inSteps)
	if len(inCatalog) != len(inSteps) {
		t.Fatalf("catalog requirements %v != step map %v", inCatalog, inSteps)
	}
	for i := range inCatalog {
		if inCatalog[i] != inSteps[i] {
			t.Fatalf("catalog requirements %v != step map %v", inCatalog, inSteps)
		}
	}
}
