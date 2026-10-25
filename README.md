# pvtr-security-slam-review

A [Privateer](https://privateerproj.com) plugin that checks a GitHub repository's evidence for the
[Security Slam](https://securityslam.com/library) Fall 2026 project badges, starting from its
Security Insights file.

Each badge runs deterministic steps first: the evidence exists and is in the right shape, and a
missing piece fails straight away. Badges with written evidence then run an AI review of its
quality, which only happens when the fixed checks did not fail.

| Badge | Requirement | Deterministic | AI review |
|---|---|---|---|
| Cleaner | SLAM-CL-01.01 | lowercase `security-insights.yml` at the root; si-tooling strict load; spec-required fields present | none |
| Chronicler | SLAM-CH-01.01 | Level 1 documentation links declared; every link resolves | each doc is real and covers its topic |
| Mechanizer | SLAM-ME-01.01 | scanner listed under tools (flags a single ad hoc run); scanner workflow on schedule/push/release; no `pull_request_target` | none |
| Inspector | SLAM-IN-01.01 | `assessments.self.evidence` declared and resolves | coverage and project-specificity |
| Defender | SLAM-DE-01.01 | grc.store target declared; result published, recurring, from a trusted publisher | none |
| Defender | SLAM-DE-01.02 | latest published result has no failed controls | written evidence for unchecked controls |
| CRA Readiness | SLAM-CR-01.01 | policy and contributing links; LF stewardship (or out-of-scope) statement verbatim in SECURITY.md | reporting process and steward escalation |

Defender reads the public grc.store hub API (`https://hub.grc.store`, override with `grc_store_url`).

## Running

```sh
make build
./security-slam debug --service <service_name> -c config.yml
```

See [example-config.yml](example-config.yml). Pick badges with `policy.applicability`. Without
`ai_provider`, `ai_model`, and `ai_api_key`, the AI steps return Needs Review.
