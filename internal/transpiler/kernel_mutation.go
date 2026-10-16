package transpiler

import (
	"strings"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
)

// Directory mutations (#142).
//
// mkdir, unlink, rmdir and both sides of rename are checked by the kernel
// against the path the operation creates or removes, through a table of its
// own: allow prefixes, deny prefixes and exact denies. The longest matching
// prefix decides (a tie denies), an exact deny always denies, and a path no
// prefix matches is denied. They have no Cedar action: a mutation of path t
// is the two FileOpenReadWrite decisions engine.DecideMutation takes, on t
// and on a new entry of t's directory (writing the directory's contents).
//
// The table is compiled here, from those Cedar decisions, as lsm.OpMutation
// rules: the single source of truth, never inferred from the open rules.
// The same regions as the open index decide it (the decision is uniform on
// each), one representative each, top down: a region whose decision
// differs from the one its nearest enclosing rule gives gets a rule at its
// point, and a single (an exact File, a directory itself) gets an exact deny
// where the table would allow it. The table has no exact allow: a single
// the table would deny but Cedar allows fails the compilation.
//
// One documented over-denial: below a FilePrefix that does not end in "/"
// (the strict form of a legacy File rule, e.g. FilePrefix::"/dev/null"),
// paths with a "/" after the prefix but not right after it
// ("/dev/nullx/y") may be denied by the kernel where Cedar allows them. The
// prefix names a file, so such paths exist only under an equally named
// directory; the kernel is stricter there, never looser.

type mutationKey struct {
	path  string
	allow bool
}

func compileMutationRules(points []pathPoint, eng *engine.Engine) ([]lsm.PolicyRule, error) {
	rs := newRegionSet(points, true)
	var loose []string
	for _, p := range points {
		if p.kind == pointPrefix && !strings.HasSuffix(p.bytes, "/") {
			loose = append(loose, p.bytes)
		}
	}
	all := append(append([]string{}, rs.prefixes...), rs.singles...)
	var keys []mutationKey
	exact := map[string]bool{}
	var exactOrder []string

	// kernel is the table's decision for path so far.
	kernel := func(path string) bool {
		if exact[path] {
			return false
		}
		best, found := mutationKey{}, false
		for _, k := range keys {
			if strings.HasPrefix(path, k.path) && (!found || len(k.path) > len(best.path)) {
				best, found = k, true
			}
		}
		return found && best.allow
	}
	put := func(path string, allow bool) {
		for i, k := range keys {
			if k.path == path {
				keys[i].allow = allow
				return
			}
		}
		keys = append(keys, mutationKey{path, allow})
	}
	mutable := func(path string) bool { return eng.DecideMutation(path).Allow }
	// fresh returns x followed by a byte no point continues with.
	fresh := func(x string) string {
		for c := byte(1); c < 0x7f; c++ {
			if c == '/' {
				continue
			}
			cand := x + string([]byte{c})
			clash := false
			for _, p := range all {
				if strings.HasPrefix(p, cand) {
					clash = true
					break
				}
			}
			if !clash {
				return cand
			}
		}
		return ""
	}

	if !rs.hasPoint("/") {
		if rep := rs.defaultRepresentative(); rep != "" && mutable(rep) {
			put("/", true)
		}
	}
	for _, x := range rs.prefixes {
		c := fresh(x)
		if c == "" {
			continue // no path is in this region
		}
		shallow, deep := mutable(c), mutable(c+"/"+string([]byte{1}))
		if kernel(c) != shallow {
			put(x, shallow)
		}
		if shallow != deep && !rs.hasPoint(x+"/") {
			// Below a loose FilePrefix: x/... is decided apart from x and
			// x<name>; x<name>/... is over-denied (documented above).
			if kernel(x+"/"+string([]byte{1})) != deep {
				put(x+"/", deep)
			}
		}
	}
	inZone := func(path string) bool {
		for _, x := range loose {
			if strings.HasPrefix(path, x) && strings.Contains(path[len(x):], "/") {
				return true
			}
		}
		return false
	}
	for _, s := range rs.singles {
		want, got := mutable(s), kernel(s)
		switch {
		case !want && got:
			exact[s] = true
			exactOrder = append(exactOrder, s)
		case want && !got && !inZone(s):
			return nil, errKernel("directory mutations (mkdir, unlink, rmdir, rename) would be allowed at exactly %s and denied around it: the kernel's mutation table has no exact allow", s)
		}
	}

	var out []lsm.PolicyRule
	for _, k := range keys {
		out = append(out, newMutationRule(k.allow, k.path, 0))
	}
	for _, s := range exactOrder {
		out = append(out, newMutationRule(false, s, lsm.ExactPath))
	}
	if len(out) == 0 {
		// Nothing is mutable; one deny marks the table as compiled.
		out = append(out, newMutationRule(false, "/", 0))
	}
	return out, nil
}

func newMutationRule(allow bool, path string, kind int32) lsm.PolicyRule {
	return newPathRule(allow, lsm.OpMutation, path, kind)
}
