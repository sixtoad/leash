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

// MigratedHeader is the first line of a file `leash policy migrate` wrote.
// The output carries no @leash_semantics marker (strict Cedar is the
// default), so the header is how migrate recognizes a file it already
// migrated.
const MigratedHeader = "// Migrated from legacy Leash policy semantics by `leash policy migrate`."

// MigrateText rewrites a legacy policy file to strict Cedar for
// `leash policy migrate`. The input is read with legacy semantics unless it
// is marked @leash_semantics("cedar") or starts with MigratedHeader: those
// are strict already (already is true and out is empty). An unmarked file
// is read as legacy because that is what migrate is for: a file written
// before strict Cedar became the default. The output is plain Cedar without
// a marker. It is checked the way a load checks it: the engine builds and
// the kernel compiles.
func MigrateText(name, text string) (out string, report RewriteReport, already bool, err error) {
	if strings.HasPrefix(strings.TrimSpace(text), MigratedHeader) {
		return "", report, true, nil
	}
	parsed, err := NewCedarParser().ParseFromNamedString(name, text)
	if err != nil {
		return "", report, false, err
	}
	marker, err := SemanticsMarker(parsed.NativePolicySet)
	if err != nil {
		return "", report, false, err
	}
	if marker == MarkerCedar {
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
	_, warnings, err := CompileKernelReport(rw.Policies, eng)
	if err != nil {
		return "", rw.Report, false, err
	}

	var b strings.Builder
	b.WriteString(MigratedHeader + "\n")
	fmt.Fprintf(&b, "// Every policy below is plain Cedar (forbid overrides permit, default deny),\n")
	fmt.Fprintf(&b, "// Leash's default dialect, and decides exactly like the legacy file did.\n")
	lines := rw.Report.Summary()
	for _, w := range warnings {
		lines = append(lines, "kernel stricter than Cedar: "+w.String())
	}
	if len(lines) > 0 {
		b.WriteString("//\n")
		for _, l := range lines {
			fmt.Fprintf(&b, "// %s\n", strings.ReplaceAll(l, "\n", " "))
		}
	}
	b.WriteString("\n")
	b.WriteString(rw.Text)
	return b.String(), rw.Report, false, nil
}
