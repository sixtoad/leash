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
	for _, file := range []string{o.defaultDenyFile, o.forbiddenWrite, o.readForbidden, o.permittedLower, o.renameSource} {
		if _, err := os.Stat(file); err != nil {
			t.Fatalf("image file %s: %v", file, err)
		}
	}
	for _, path := range []string{o.renameTarget, o.renameOKTo, o.defaultDenyDir + "/leash-ovl-new", o.permittedDir + "/leash-ovl-new"} {
		_ = os.Remove(path)
	}
	if err := os.WriteFile(o.renameOKFrom, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
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
	})
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
