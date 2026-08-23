package darwind

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/strongdm/leash/internal/macext"
)

// darwinHealthHandler serves /health/darwin: the macOS enforcement facts only
// the running daemon can see — which extensions actually hold a websocket to
// it, and whether LeashES reported getting Full Disk Access.
//
// `leash doctor` reads this from outside the process. Without it, doctor would
// have to guess at a permission macOS does not let one process read on
// another's behalf, and would have no way at all to tell an extension that is
// merely activated from one that is activated AND receiving rules (leash #62).
//
// It always answers 200. "The daemon is up and knows nothing yet" is itself an
// answer doctor needs, and a 503 here would be indistinguishable from the
// daemon being down — which has a completely different remedy.
//
// The snapshot arrives as a function rather than a *macsync.Manager so this
// file needs no build tag: the handler is then testable on any host, which is
// the only way its "no manager yet" branch ever gets exercised.
func darwinHealthHandler(snapshot func() macext.DaemonHealth) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		health := macext.DaemonHealth{Components: []string{}, FullDiskAccess: macext.FDAUnknown.String()}
		if snapshot != nil {
			health = snapshot()
		}
		if health.Components == nil {
			// [] rather than null, for the same reason doctor's own document
			// never emits null arrays: a consumer that has to handle both forms
			// will eventually handle one of them wrong.
			health.Components = []string{}
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if err := json.NewEncoder(w).Encode(health); err != nil {
			log.Printf("failed to encode darwin health: %v", err)
		}
	}
}
