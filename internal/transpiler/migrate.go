package transpiler

import (
	"fmt"
	"strings"

	"github.com/strongdm/leash/internal/engine"
)

// Summary renders the report as one line per change, for logs and the
// migrate command.
func (r RewriteReport) Summary() []string {
	var out []string
	for _, e := range r.Exceptions {
		out = append(out, "exception: "+e.String())
	}
	for _, n := range r.Notes {
		out = append(out, "note: "+n.String())
	}
	for _, s := range r.Synthesized {
		out = append(out, "added: "+s)
	}
	return out
}

// MigrateText rewrites a legacy policy file to strict Cedar for
// `leash policy migrate`. already reports a file that is strict already
// (out is then empty). The result is checked the way a load checks it: the
// engine builds and the kernel compiles.
func MigrateText(name, text string) (out string, report RewriteReport, already bool, err error) {
	parsed, err := NewCedarParser().ParseFromNamedString(name, text)
	if err != nil {
		return "", report, false, err
	}
	sem, err := DetectSemantics(parsed.NativePolicySet)
	if err != nil {
		return "", report, false, err
	}
	if sem == SemanticsCedar {
		return "", report, true, nil
	}
	rw, err := RewriteLegacy(RewriteOptions{Name: name}, LegacyLayer{Name: name, Policies: parsed})
	if err != nil {
		return "", report, false, err
	}
	eng, err := engine.New(rw.Policies)
	if err != nil {
		return "", rw.Report, false, err
	}
	if _, err := CompileKernel(rw.Policies, eng); err != nil {
		return "", rw.Report, false, err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "// Migrated from legacy Leash policy semantics by `leash policy migrate`.\n")
	fmt.Fprintf(&b, "// Every policy below is plain Cedar (forbid overrides permit, default deny)\n")
	fmt.Fprintf(&b, "// and decides exactly like the legacy file did.\n")
	if lines := rw.Report.Summary(); len(lines) > 0 {
		b.WriteString("//\n")
		for _, l := range lines {
			fmt.Fprintf(&b, "// %s\n", strings.ReplaceAll(l, "\n", " "))
		}
	}
	b.WriteString("\n")
	b.WriteString(rw.Text)
	return b.String(), rw.Report, false, nil
}
