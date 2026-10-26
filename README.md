# pvtr-security-slam-review

This is the scanner we use to review [Security Slam](https://securityslam.com/library) Fall 2026
badge submissions. You can run it on your own project to see what a reviewer will see before you submit.

## What it does

For each Slam badge (Cleaner, Chronicler, Mechanizer, Inspector, Defender, CRA Readiness) it
gathers the evidence your repository offers, starting from your Security Insights file, and
reports what it found. **It does not award badges.** Every result, AI verdicts included, is a
finding for a human reviewer to read.

Each badge runs fixed checks first: does the evidence exist, and is it in the right shape. Badges
with written evidence then get an AI review of its quality, but only when the fixed checks did not fail.

## Prerequisites

- **Go** (the version in [go.mod](go.mod)).
- **[`pvtr`](https://privateerproj.com)**, the Privateer CLI, if you want to run it as a plugin. Not needed for `go run . debug`.
- **A GitHub token** that can read public repositories.
- **An Anthropic API key** (optional). Only the AI review steps use it: Chronicler, Inspector,
  Defender's written-evidence step, and CRA Readiness. Without a key those steps return
  **Needs Review**. Cleaner, Mechanizer, and every fixed check run without it.

## Configure

Save this as `config.yml` (it is git-ignored, so your token stays local):

```yaml
loglevel: info
write-directory: evaluation_results
output: yaml
targets:
  my-project:
    plugin: local/security-slam # the name pvtr gives a locally installed plugin
    policy:
      catalogs:
        - security-slam-fall-2026
      applicability: # the badges you are going for; unlisted badges are skipped, not failed
        - cleaner
        - chronicler
        - mechanizer
        - inspector
        - defender
        - cra-readiness
    vars:
      owner: <github org or user>
      repo: <github repo>
      token: <github token>
      maturity_level: 1 # Sandbox = 1, Incubating = 2, Graduated = 3
      grc_store_target: <namespace>/<target> # Defender only: where your pvtr-publish-results workflow publishes
      # Optional AI review:
      ai_provider: anthropic
      ai_model: claude-sonnet-5-5
      ai_api_key: <anthropic api key>
```

`maturity_level` is required when Chronicler or Defender is listed; the target fails to load
without it. Without `grc_store_target`, Defender returns Needs Review. See
[example-config.yml](example-config.yml) for every option.

## Run

```sh
go run . debug --target=my-project -c config.yml
```

Results print to the terminal and are written under `evaluation_results/`.

To run through Privateer instead, `make build`, then `pvtr install --local ./security-slam` and
`pvtr run`. Note that `pvtr run --target` currently runs every target in the config, not just
the one you name, so use `go run . debug --target` when you want one.

## Reading results

- **Passed**: the evidence is there and, where AI review applies, it holds up.
- **Failed**: something is missing or wrong, and the message says what.
- **Needs Review**: the scanner could not decide (no AI key, a low-confidence AI verdict, a link
  it could not fetch, or a Defender control the OSPS Baseline scanner leaves to a human). A
  reviewer will look at it; you can help by making the evidence easy to find.

Two things worth knowing:

- **Stale scanner results.** Defender reads your latest OSPS Baseline result from grc.store. If it
  was published with a scanner older than v0.33.1, some failures are scanner bugs fixed in that
  release, not problems in your project. Those are named as stale scanner results; re-publish
  with v0.33.1 or later to clear them.
- **Finding your Security Insights file.** The file is located with
  [si-tooling](https://github.com/ossf/si-tooling): `security-insights.yml` or `.yaml`, at the
  repository root or in `.github/`, on the default branch. Keep only one per location.

## What each badge checks

| Badge | Requirement | Fixed checks | AI review |
|---|---|---|---|
| Cleaner | SLAM-CL-01.01 | a Security Insights file found by si-tooling (`security-insights.yml` or `.yaml`, at the root or in `.github/`, plus the legacy names si-tooling accepts), and only one per location; si-tooling strict load; spec-required fields present; validates against the spec's v2.2.0 CUE schema; `repository.url` is the reviewed repository | none |
| Chronicler | SLAM-CH-01.01 | Level 1 documentation links declared; every link resolves; the OSPS Baseline scanner's steps for the documentation-shaped DO, GV, and VM controls pass at `maturity_level` | each doc is real and covers its topic |
| Mechanizer | SLAM-ME-01.01 | scanner listed under tools (flags a single ad hoc run); a scanner workflow on schedule, or push or release reaching the default branch; a run from that trigger in the last 30 days | none |
| Inspector | SLAM-IN-01.01 | `assessments.self.evidence` declared and resolves; a Gemara threat catalog validates against the Gemara v1.6.0 CUE schema and has threats | coverage and project-specificity; notes evidence not committed to the repository |
| Defender | SLAM-DE-01.01 | `grc_store_target` set; result published; trusted runs on two or more days, the newest within 30 days; target verified by GitHub OIDC and the latest result signed by `pvtr-publish-results` from this repository (grc.store's own verification, not rechecked) | none |
| Defender | SLAM-DE-01.02 | latest published result has no failed controls at the project's maturity level (levels are cumulative), and the scan ran at that level; controls the scanner's catalog tags only for lower levels, and Unknown controls, are marked for review; the scanner version is reported, and results from scanners older than v0.33.1 showing the bugs fixed there (QA-05.01/05.02 Unknown, BR-01.01 workflow parse errors, BR-07.01/VM-02.01 skipped) are marked as stale scanner results, not project failures | written evidence for Needs Review and Not Run controls |
| CRA Readiness | SLAM-CR-01.01 | policy and contributing links; LF stewardship (or out-of-scope) statement verbatim in the linked policy (SECURITY.md when none is linked); a named GitHub private reporting channel is enabled; the contributing guide names `steward@linuxfoundation.org`. A steward outside the LF is marked for review; failures link the security policy | reporting process and steward escalation |

## Getting help

Questions or a result you think is wrong: open an issue on
[eddie-knight/pvtr-security-slam-review](https://github.com/eddie-knight/pvtr-security-slam-review/issues).
Include the badge, the requirement ID (for example `SLAM-CL-01.01`), and the message you got.

For everything else about the Slam (badges, dates, submitting), see [securityslam.com](https://securityslam.com).
