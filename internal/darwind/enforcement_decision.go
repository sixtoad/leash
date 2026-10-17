package darwind

import (
	"fmt"
	"strings"

	"github.com/strongdm/leash/internal/macext"
)

// This file is not build-tagged: the decision is pure and unit-tested on any OS.

// decideDarwinEnforcement is the policy of the native macOS preflight. Native
// --darwin mode enforces only through the ES and NE system extensions; there is
// no proxy fallback, so a missing extension means part of the policy is not
// enforced at all. It returns nil only when both are active. There is no
// opt-out: running --darwin without its enforcement layer would give exactly
// the false sense of safety leash exists to prevent.
func decideDarwinEnforcement(esID, neID string, es, ne macext.State, queryErr string) error {
	if es == macext.StateActive && ne == macext.StateActive {
		return nil
	}
	return fmt.Errorf("native macOS enforcement is unavailable, so leash will not start (native --darwin mode has no fallback layer; running unenforced is not supported)\n%s",
		darwinEnforcementAdvice(esID, neID, es, ne, queryErr))
}

func darwinEnforcementAdvice(esID, neID string, es, ne macext.State, queryErr string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "  Endpoint Security extension (%s): %s\n", esID, es.Describe())
	fmt.Fprintf(&b, "  Network Filter extension   (%s): %s\n", neID, ne.Describe())
	if strings.TrimSpace(queryErr) != "" {
		fmt.Fprintf(&b, "  systemextensionsctl list failed: %s\n", queryErr)
	}
	b.WriteString(`Activate them:
  1. open Leash.app and click Activate for both extensions
  2. approve in System Settings > General > Login Items & Extensions
  3. grant the Endpoint Security extension Full Disk Access
     (System Settings > Privacy & Security > Full Disk Access)
See docs/MACOS.md, or run 'leash doctor' for the full macOS readiness report.`)
	return b.String()
}
