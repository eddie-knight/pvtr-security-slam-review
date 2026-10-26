# pvtr-security-slam-review

A [Privateer](https://privateerproj.com) plugin that checks a GitHub repository's evidence for the
[Security Slam](https://securityslam.com/library) Fall 2026 project badges, starting from its
Security Insights file.

Each badge runs deterministic steps first: the evidence exists and is in the right shape, and a
missing piece fails straight away. Badges with written evidence then run an AI review of its
quality, which only happens when the fixed checks did not fail.

| Badge | Requirement | Deterministic | AI review |
|---|---|---|---|
| Cleaner | SLAM-CL-01.01 | lowercase `security-insights.yml` at the root, and only one; si-tooling strict load; spec-required fields present; validates against the spec's v2.2.0 CUE schema; `repository.url` is the reviewed repository | none |
| Chronicler | SLAM-CH-01.01 | Level 1 documentation links declared; every link resolves; the OSPS Baseline scanner's steps for the documentation-shaped DO, GV, and VM controls pass at `maturity_level` | each doc is real and covers its topic |
| Mechanizer | SLAM-ME-01.01 | scanner listed under tools (flags a single ad hoc run); a scanner workflow on schedule, or push or release reaching the default branch; a run from that trigger in the last 30 days | none |
| Inspector | SLAM-IN-01.01 | `assessments.self.evidence` declared and resolves; a Gemara threat catalog validates against the Gemara v1.6.0 CUE schema and has threats | coverage and project-specificity; notes evidence not committed to the repository |
| Defender | SLAM-DE-01.01 | `grc_store_target` set; result published; trusted runs on two or more days, the newest within 30 days; target verified by GitHub OIDC and the latest result signed by `pvtr-publish-results` from this repository (grc.store's own verification, not rechecked) | none |
| Defender | SLAM-DE-01.02 | latest published result has no failed controls at the project's maturity level (levels are cumulative), and the scan ran at that level; controls the scanner's catalog tags only for lower levels, and Unknown controls, are marked for review | written evidence for Needs Review and Not Run controls |
| CRA Readiness | SLAM-CR-01.01 | policy and contributing links; LF stewardship (or out-of-scope) statement verbatim in the linked policy (SECURITY.md when none is linked); a named GitHub private reporting channel is enabled; the contributing guide names `steward@linuxfoundation.org`. A steward outside the LF is marked for review; failures link the security policy | reporting process and steward escalation |

Every result is a finding for the reviewer to read, AI verdicts included; the plugin does not award badges.
Repository files and this repository's default-branch blob links are read at the branch head when the run starts; the result's target `version` records that commit.
A target that cannot load (empty `owner` or `repo`, bad `maturity_level`) logs an error and exits non-zero.

Defender reads the public grc.store hub API (`https://hub.grc.store`, override with `grc_store_url`).

## Running

```sh
make build
./security-slam debug --service <service_name> -c config.yml
```

See [example-config.yml](example-config.yml). Pick badges with `policy.applicability`. Without
`ai_provider`, `ai_model`, and `ai_api_key`, the AI steps return Needs Review, as do low-confidence AI verdicts.
Chronicler and Defender need `maturity_level` (1-3), set by whoever runs the review; the project does not choose it.
Defender also needs `grc_store_target` (`<namespace>/<target>`, the target the project's pvtr-publish-results workflow publishes to); without it the Defender steps return Needs Review.
