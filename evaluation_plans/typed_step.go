package evaluation_plans

import (
	"github.com/eddie-knight/pvtr-security-slam-review/data"
	"github.com/gemaraproj/go-gemara"
)

// TypedStep is the signature every step in this plugin uses: it receives a
// fully-typed data.Payload instead of an untyped any. The SDK's typed
// registration helpers adapt it to gemara.AssessmentStep.
//
// Always register through those helpers. Wrapping a TypedStep in a local
// closure erases its function name from the evaluation log.
type TypedStep func(data.Payload) (gemara.Result, string, gemara.ConfidenceLevel)

// AllSteps returns every step map in this package, keyed by assessment ID.
func AllSteps() map[string][]TypedStep {
	return Slam
}
