package doctor

import (
	"bytes"
	"strings"
	"testing"
)

// doctor reports stale native boxes on stderr (stdout/JSON unchanged) and only
// reaps them with --reap (#158).
func TestReportStaleNativeBoxes(t *testing.T) {
	origList, origReap := staleNativeBoxes, reapNativeBoxes
	t.Cleanup(func() { staleNativeBoxes, reapNativeBoxes = origList, origReap })
	reaped := false
	staleNativeBoxes = func() []string { return []string{"leash-native-a-1"} }
	reapNativeBoxes = func() []string { reaped = true; return []string{"leash-native-a-1"} }

	var stderr bytes.Buffer
	reportStaleNativeBoxes(&stderr, false)
	if reaped || !strings.Contains(stderr.String(), "leash-native-a-1") || !strings.Contains(stderr.String(), "--reap") {
		t.Fatalf("report-only: reaped=%v stderr=%q", reaped, stderr.String())
	}
	stderr.Reset()
	reportStaleNativeBoxes(&stderr, true)
	if !reaped || !strings.Contains(stderr.String(), "reaped 1") {
		t.Fatalf("--reap: reaped=%v stderr=%q", reaped, stderr.String())
	}
}

// Doctor tests must not query the host's container engines for stale runs.
func init() {
	staleContainerRuns = func() []string { return nil }
	reapContainerRuns = func() []string { return nil }
}

// Stale containers of dead container runs are reported on stderr, and removed
// only with --reap (#201).
func TestReportStaleContainerRuns(t *testing.T) {
	origList, origReap := staleContainerRuns, reapContainerRuns
	t.Cleanup(func() { staleContainerRuns, reapContainerRuns = origList, origReap })
	reaped := false
	staleContainerRuns = func() []string { return []string{"docker:agent", "docker:agent-leash"} }
	reapContainerRuns = func() []string { reaped = true; return []string{"docker:agent", "docker:agent-leash"} }

	var stderr bytes.Buffer
	reportStaleContainerRuns(&stderr, false)
	if reaped || !strings.Contains(stderr.String(), "docker:agent-leash") || !strings.Contains(stderr.String(), "--reap") {
		t.Fatalf("report-only: reaped=%v stderr=%q", reaped, stderr.String())
	}
	stderr.Reset()
	reportStaleContainerRuns(&stderr, true)
	if !reaped || !strings.Contains(stderr.String(), "removed 2") {
		t.Fatalf("--reap: reaped=%v stderr=%q", reaped, stderr.String())
	}
}
