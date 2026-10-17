//go:build linux

package lsm

// Container-mode overlay rootfs cases for the real-kernel load validation
// (issues #186/#125). The validation binary runs inside a Docker container
// whose rootfs is overlayfs, so its image files are exactly what a governed
// workload writes. The file-open module is loaded with containerOverlay=true,
// as leashd does for container runs, which installs the copy-up correlation
// and its syscall-exit cleanup.
//
// Before the fix a separate lsm/file_open marker program ran ahead of
// lsm_open (BPF trampolines run the most recently attached link first) and
// allowed every write open on the overlay, whatever the policy said. A
// rename-source check was skipped the same way once the destination half,
// which the kernel also runs first, had allowed its endpoint.

import (
	"bytes"
	"os"
	"regexp"
	"syscall"
	"testing"
)

const overlayfsSuperMagic = 0x794c7630

type overlayRootCases struct {
	defaultDenyFile string // image file under no rule (default deny)
	defaultDenyDir  string // image directory under no rule
	forbiddenWrite  string // image file under the generic /etc/ allow with a :rw forbid
	readForbidden   string // image file with a generic forbid
	permittedLower  string // lower-layer image file under the generic /etc/ allow (copy-up)
	permittedDir    string // image directory under the generic /etc/ allow
	renameSource    string // image file under no rule, renamed into a permitted dir
	renameTarget    string
	renameOKFrom    string // rename inside the permitted rw dir (control)
	renameOKTo      string
	uringPermitted  string // overlay file in the permitted rw dir, opened first
	uringHelper     string // copy of this test binary where the box may exec it
	linkSource      string // readable lower-layer image file
	linkTarget      string // in the permitted rw dir
}

func newOverlayRootCases() overlayRootCases {
	return overlayRootCases{
		defaultDenyFile: "/root/.bashrc",
		defaultDenyDir:  "/opt",
		forbiddenWrite:  "/etc/debian_version",
		readForbidden:   "/etc/shadow", // kernelLoadPolicy forbids it
		permittedLower:  "/etc/issue.net",
		permittedDir:    "/etc",
		renameSource:    "/root/.profile",
		renameTarget:    "/tmp/leash-ovl-moved-profile",
		renameOKFrom:    "/tmp/leash-ovl-from",
		renameOKTo:      "/tmp/leash-ovl-to",
		uringPermitted:  "/tmp/leash-ovl-uring-ok",
		uringHelper:     "/usr/local/bin/leash-ovl-uring-helper",
		linkSource:      "/etc/issue",
		linkTarget:      "/tmp/leash-ovl-issue-link",
	}
}

// policy adds only the forbid; the other cases rely on kernelLoadPolicy's
// default deny, generic /etc/ allow, /etc/shadow forbid and /tmp/ rw allow.
func (o overlayRootCases) policy() []string {
	return []string{"deny file.open:rw " + o.forbiddenWrite}
}

// prepare fails the gate when the rootfs is not overlayfs: these cases must
// not pass vacuously on a plain filesystem.
func (o overlayRootCases) prepare(t *testing.T) {
	t.Helper()
	var fs syscall.Statfs_t
	if err := syscall.Statfs("/", &fs); err != nil {
		t.Fatalf("statfs /: %v", err)
	}
	if fs.Type != overlayfsSuperMagic {
		t.Fatalf("container rootfs is not overlayfs (magic %#x); run via scripts/verify-lsm-kernel-load.sh with an overlay storage driver", fs.Type)
	}
	for _, file := range []string{o.defaultDenyFile, o.forbiddenWrite, o.readForbidden, o.permittedLower, o.renameSource, o.linkSource} {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("image file %s: %v", file, err)
		}
	}
	for _, path := range []string{o.renameTarget, o.renameOKTo, o.linkTarget, o.linkTarget + "-denied", o.defaultDenyDir + "/leash-ovl-new", o.permittedDir + "/leash-ovl-new"} {
		_ = os.Remove(path)
	}
	for _, file := range []string{o.renameOKFrom, o.uringPermitted} {
		if err := os.WriteFile(file, []byte("x"), 0o666); err != nil {
			t.Fatal(err)
		}
	}
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.uringHelper, self, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(o.uringHelper) })
}

func (o overlayRootCases) verify(t *testing.T, cgroupFD int) {
	t.Helper()
	runBoxCases(t, cgroupFD, []boxCase{
		{"overlay: write default-deny image file", boxWrite, []string{o.defaultDenyFile}, false, ""},
		{"overlay: append default-deny image file", `echo x >> "$1"`, []string{o.defaultDenyFile}, false, ""},
		{"overlay: O_CREAT in default-deny image dir", boxWrite, []string{o.defaultDenyDir + "/leash-ovl-new"}, false, ""},
		{"overlay: write image file under :rw forbid", boxWrite, []string{o.forbiddenWrite}, false, ""},
		{"overlay: read image file under :rw forbid (read still permitted)", boxRead, []string{o.forbiddenWrite}, true, ""},
		{"overlay: read forbidden image file", boxRead, []string{o.readForbidden}, false, ""},
		{"overlay: read default-deny image file", boxRead, []string{o.defaultDenyFile}, false, ""},
		{"overlay: write permitted lower-layer image file (copy-up)", `echo x >> "$1"`, []string{o.permittedLower}, true, ""},
		{"overlay: O_CREAT in permitted image dir", boxWrite, []string{o.permittedDir + "/leash-ovl-new"}, true, ""},
		{"overlay: rename default-deny image file into permitted rw dir", `mv "$1" "$2"`, []string{o.renameSource, o.renameTarget}, false, ""},
		{"overlay: rename inside permitted rw dir", `mv "$1" "$2"`, []string{o.renameOKFrom, o.renameOKTo}, true, ""},
		// The link copies the lower-layer source up; its backing opens ride the
		// correlation the allowed link installs (#29).
		{"overlay: hard-link readable lower-layer image file into permitted rw dir", boxLink, []string{o.linkSource, o.linkTarget}, true, ""},
		{"overlay: hard-link default-deny image file into permitted rw dir", boxLink, []string{o.defaultDenyFile, o.linkTarget + "-denied"}, false, eperm},
	})
	o.verifyURing(t, cgroupFD)
	if _, err := os.Stat(o.renameTarget); err == nil {
		t.Errorf("FAIL overlay: denied rename still moved %s to %s", o.renameSource, o.renameTarget)
	}
	if data, err := os.ReadFile(o.permittedLower); err != nil || !bytes.HasSuffix(data, []byte("x\n")) {
		t.Errorf("FAIL overlay: permitted copy-up write did not land in %s (%v)", o.permittedLower, err)
	}
}

// auditPatterns are records the overlay cases must leave in the event log.
func (o overlayRootCases) auditPatterns() []string {
	return []string{
		`event=file.open:rw .*path="` + regexp.QuoteMeta(o.defaultDenyFile) + `" decision=denied`,
		`event=file.open:rw .*path="` + regexp.QuoteMeta(o.forbiddenWrite) + `" decision=denied`,
		`event=file.open:rw .*path="` + regexp.QuoteMeta(o.permittedLower) + `" decision=allowed`,
		`event=file.rename .*path="` + regexp.QuoteMeta(o.renameSource) + `" decision=denied`,
	}
}
