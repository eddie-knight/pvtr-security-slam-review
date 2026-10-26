package evaluation_plans

import (
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/reusable_steps"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/slam/chronicler"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/slam/cleaner"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/slam/cra"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/slam/defender"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/slam/inspector"
	"github.com/eddie-knight/pvtr-security-slam-review/evaluation_plans/slam/mechanizer"
)

var (
	// Slam contains assessment step implementations for the Security Slam
	// badge catalog. Each badge runs its deterministic steps first and its AI
	// review last: a Failed step stops the assessment, so the AI step only
	// runs once the evidence exists and is in the right shape.
	Slam = map[string][]TypedStep{
		"SLAM-CL-01.01": {
			cleaner.SecurityInsightsFileFound,
			cleaner.ValidatesWithSITooling,
			cleaner.RequiredFieldsPresent,
			cleaner.ValidatesAgainstSchema,
			cleaner.RepositoryURLMatches,
		},
		"SLAM-CH-01.01": {
			reusable_steps.HasSecurityInsightsFile,
			chronicler.DocumentationLinksPresent,
			chronicler.DocumentationLinksResolve,
			chronicler.BaselineDocumentationControlsMet,
			chronicler.AIReviewDocumentation,
		},
		"SLAM-ME-01.01": {
			reusable_steps.HasSecurityInsightsFile,
			mechanizer.BaselineScannerListedInTools,
			mechanizer.ScannerWorkflowRequirements,
		},
		"SLAM-IN-01.01": {
			reusable_steps.HasSecurityInsightsFile,
			inspector.SelfAssessmentDeclared,
			inspector.SelfAssessmentResolves,
			inspector.GemaraCatalogWellFormed,
			inspector.AIReviewSelfAssessment,
		},
		"SLAM-DE-01.01": {
			reusable_steps.HasSecurityInsightsFile,
			defender.GrcStoreTargetDeclared,
			defender.ResultPublished,
			defender.ResultIsRecurring,
			defender.TrustedPublisher,
		},
		"SLAM-DE-01.02": {
			reusable_steps.HasSecurityInsightsFile,
			defender.GrcStoreTargetDeclared,
			defender.ResultPublished,
			defender.LatestResultHasNoFailures,
			defender.AIReviewUncheckedControlEvidence,
		},
		"SLAM-CR-01.01": {
			reusable_steps.HasSecurityInsightsFile,
			cra.SecurityInsightsLinksPresent,
			cra.SecurityPolicyHasStewardStatement,
			cra.ReportingChannelsWork,
			cra.AIReviewReadiness,
		},
	}
)
