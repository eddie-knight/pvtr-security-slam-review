package main

import (
	"embed"
	"fmt"
	"path/filepath"

	"os"

	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans"
	"github.com/gemaraproj/go-gemara"

	"github.com/privateerproj/privateer-sdk/command"
	"github.com/privateerproj/privateer-sdk/config"
	"github.com/privateerproj/privateer-sdk/pluginkit"
	"github.com/privateerproj/privateer-sdk/shared"
	"github.com/spf13/cobra"
)

var (
	// Version is to be replaced at build time by the associated tag
	Version = "0.0.0"
	// VersionPostfix is a marker for the version such as "dev", "beta", "rc", etc.
	VersionPostfix = "dev"
	// GitCommitHash is the commit at build time
	GitCommitHash = ""
	// BuiltAt is the actual build datetime
	BuiltAt = ""

	PluginName   = "security-slam"
	RequiredVars = []string{
		"owner",
		"repo",
	}
	//go:embed data/catalogs
	files   embed.FS
	dataDir = filepath.Join("data", "catalogs")

	// evaluatedCommit carries the Loader's commit to the target builder, which
	// the SDK gives only the config.
	evaluatedCommit string
)

func main() {
	if VersionPostfix != "" {
		Version = fmt.Sprintf("%s-%s", Version, VersionPostfix)
	}
	if GitCommitHash != "" {
		Version = fmt.Sprintf("%s+%s", Version, GitCommitHash)
	}

	orchestrator, err := newOrchestrator()
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(shared.InternalError)
	}

	runCmd := command.NewPluginCommands(
		PluginName,
		Version,
		GitCommitHash,
		BuiltAt,
		orchestrator,
	)

	exitLikeStart(runCmd, orchestrator)

	err = runCmd.Execute()
	if err != nil {
		os.Exit(shared.InternalError)
	}
}

// exitLikeStart makes debug mode exit with the code a privateer run gets: the
// SDK's debug command prints a config or load error and exits 0, so a target
// that never ran reads as a pass.
func exitLikeStart(runCmd *cobra.Command, orchestrator *pluginkit.EvaluationOrchestrator) {
	for _, cmd := range runCmd.Commands() {
		if cmd.Name() != "debug" {
			continue
		}
		cmd.Run = func(cmd *cobra.Command, args []string) {
			cmd.Print("Running in debug mode\n")
			err := orchestrator.Mobilize()
			if err != nil {
				cmd.Println(err)
			}
			os.Exit(pluginkit.ExitCodeFor(orchestrator, err))
		}
	}
}

func newOrchestrator() (*pluginkit.EvaluationOrchestrator, error) {
	orchestrator := &pluginkit.EvaluationOrchestrator{
		PluginName:    PluginName,
		PluginVersion: Version,
		PluginUri:     "https://github.com/eddie-knight/pvtr-security-slam-review",
		Publisher:     "eddie-knight",
		License:       "Apache-2.0",
	}
	orchestrator.AddLoader(func(c *config.Config) (any, error) {
		payload, err := data.Loader(c)
		if p, ok := payload.(data.Payload); ok {
			evaluatedCommit = p.Commit
		}
		return payload, err
	})
	orchestrator.AddTargetBuilder(func(c *config.Config) gemara.Resource {
		slug := fmt.Sprintf("%s/%s", c.GetString("owner"), c.GetString("repo"))
		return gemara.Resource{
			Id:   fmt.Sprintf("github.com/%s", slug),
			Name: slug,
			Type: gemara.Software,
			Uri:  fmt.Sprintf("https://github.com/%s", slug),
			// The default branch commit every repository file was read at.
			Version: evaluatedCommit,
		}
	})

	if err := orchestrator.AddReferenceCatalogs(dataDir, files); err != nil {
		return nil, fmt.Errorf("error loading catalog: %w", err)
	}

	orchestrator.AddRequiredVars(RequiredVars)

	if err := pluginkit.AddEvaluationSuiteTypedForAllCatalogs(orchestrator, nil, evaluation_plans.AllSteps()); err != nil {
		return nil, fmt.Errorf("error adding evaluation suites: %w", err)
	}
	return orchestrator, nil
}
