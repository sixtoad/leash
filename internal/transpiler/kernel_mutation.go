package transpiler

import (
	"strings"

	"github.com/strongdm/leash/internal/engine"
	"github.com/strongdm/leash/internal/lsm"
)

// Directory mutations (#142).
//
// mkdir, unlink, rmdir and both sides of rename are checked by the kernel
// against the path the operation creates or removes, through a table of
// its own: the operation is denied under any deny prefix or exact deny, else
// allowed under any allow prefix, else denied (deny first, no
// specificity). They have no Cedar action: a mutation of path t is the two
// FileOpenReadWrite decisions engine.DecideMutation takes, on t and on a new
// entry of t's directory (writing the directory's contents).
//
// The table is compiled here, from those Cedar decisions, as lsm.OpMutation
// rules: the single source of truth, never inferred from the open rules.
// The same regions as the open index decide it (the decision is uniform on
// each), one representative each, top down:
//
//   - a region whose decision differs from what the table already gives it
//     gets an allow prefix or a deny prefix at its point;
//   - a single (an exact File, a directory itself) gets an exact deny where
//     the table would allow it;
//   - an allow that a deny prefix above it would shadow (a permit nested in
//     a forbid nested in a permit, for mutations) cannot be expressed by a
//     deny-first table and fails the compilation, naming both paths.
//
// One documented over-denial: below a FilePrefix that does not end in "/"
// (the strict form of a legacy File rule, e.g. FilePrefix::"/dev/null"),
// paths with a "/" after the prefix ("/dev/null/x", "/dev/nullx/y") may be
// denied by the kernel where Cedar allows them. The prefix names a file, so
// such paths exist only under an equally named directory; the kernel is
// stricter there, never looser.

func compileMutationRules(points []pathPoint, eng *engine.Engine) ([]lsm.PolicyRule, error) {
	rs := newRegionSet(points, true)
	var loose []string
	for _, p := range points {
		if p.kind == pointPrefix && !strings.HasSuffix(p.bytes, "/") {
			loose = append(loose, p.bytes)
		}
	}
	all := append(append([]string{}, rs.prefixes...), rs.singles...)
	var allows, denies []string
	exact := map[string]bool{}
	var exactOrder []string

	coveredBy := func(path string, keys []string) string {
		for _, k := range keys {
			if strings.HasPrefix(path, k) {
				return k
			}
		}
		return ""
	}
	kernel := func(path string) bool {
		if coveredBy(path, denies) != "" || exact[path] {
			return false
		}
		return coveredBy(path, allows) != ""
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
	shadowed := func(path, deny string) error {
		return errKernel("directory mutations (mkdir, unlink, rmdir, rename) would be allowed at %s but denied above it at %s: the kernel's mutation table gives a deny prefix precedence over any allow below it, so a permit nested in a forbid nested in a permit cannot be enforced for mutations", path, deny)
	}

	if !rs.hasPoint("/") {
		if rep := rs.defaultRepresentative(); rep != "" && mutable(rep) {
			allows = append(allows, "/")
		}
	}
	for _, x := range rs.prefixes {
		c := fresh(x)
		if c == "" {
			continue // no path is in this region
		}
		shallow, deep := mutable(c), mutable(c+"/"+string([]byte{1}))
		cur := kernel(c)
		switch {
		case shallow == deep:
			if cur == shallow {
				continue
			}
			if shallow {
				if d := coveredBy(c, denies); d != "" {
					return nil, shadowed(x, d)
				}
				allows = append(allows, x)
			} else {
				denies = append(denies, x)
			}
		case !shallow && deep:
			// Below a loose FilePrefix: deny the region, over-denying the
			// paths with a "/" after it (documented above).
			if cur {
				denies = append(denies, x)
			}
		default:
			return nil, errKernel("internal error: mutation of %q denied below an allowed entry", c)
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
			if d := coveredBy(s, denies); d != "" {
				return nil, shadowed(s, d)
			}
			return nil, errKernel("directory mutations would be allowed at exactly %s and denied around it: the kernel's mutation table has no exact allow", s)
		}
	}

	var out []lsm.PolicyRule
	if len(allows) == 0 {
		// Nothing is mutable; one deny marks the table as compiled.
		return []lsm.PolicyRule{newMutationRule(false, "/", 0)}, nil
	}
	for _, a := range allows {
		out = append(out, newMutationRule(true, a, 0))
	}
	for _, d := range denies {
		out = append(out, newMutationRule(false, d, 0))
	}
	for _, s := range exactOrder {
		out = append(out, newMutationRule(false, s, lsm.ExactPath))
	}
	return out, nil
}

func newMutationRule(allow bool, path string, kind int32) lsm.PolicyRule {
	return newPathRule(allow, lsm.OpMutation, path, kind)
}
