package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type lifecycleAuditWriter struct {
	bytes.Buffer
	source  string
	existed bool
}

func (w *lifecycleAuditWriter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte(`"type":"leash_audit"`)) {
		_, err := os.Stat(w.source)
		w.existed = err == nil
	}
	return w.Buffer.Write(p)
}

func TestLifecycleAuditExportPrecedesTemporaryCleanup(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "events.log")
	if err := os.WriteFile(path, []byte("event=file.open decision=deny path=/work/main.go\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out := &lifecycleAuditWriter{source: path}
	r := &runner{cfg: config{workDir: root, workDirIsTemp: true, logDir: root}, lifecycleTelemetry: lifecycleTestSink(t, out)}
	if err := r.stopContainers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !out.existed {
		t.Fatal("audit read after source removal")
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("temporary state retained: %v", err)
	}
	records := lifecycleRecords(t, out.String())
	if len(records) != 3 || records[0]["name"] != "cleanup" || records[1]["type"] != "leash_audit" {
		t.Fatalf("records: %v", records)
	}
	terminal := records[2]
	if terminal["type"] != "leash_export" || terminal["status"] != "complete" || terminal["source_bytes_dropped"] != float64(0) || terminal["event_bytes_dropped"] != float64(0) {
		t.Fatalf("complete audit export missing terminal evidence: %v", terminal)
	}
	before := out.Len()
	r.exportLifecycleAudit()
	if out.Len() != before {
		t.Fatal("duplicate export")
	}
}

func TestLifecycleAuditRedactsBeforeWrite(t *testing.T) {
	var out bytes.Buffer
	t.Setenv("GITEA_TOKEN", "fake-env-credential-1234")
	sink := lifecycleTestSink(t, &out)
	extra, err := newLifecycleRedactor(`["arbitrary-grant-material","grant-line-one\ngrant-line-two"]`)
	if err != nil {
		t.Fatal(err)
	}
	sink.redactor = extra
	text := "event=deny value=fake-env-credential-1234\n" +
		"Authorization: Bearer short-secret\n" +
		`{"token":"x","nested":{"apiKey":"tiny","grant":{"arbitrary":"private-grant-body"}},"path":"/work/read.go"}` + "\n" +
		"event=deny content=arbitrary-grant-material\n" +
		"grant-line-one\ngrant-line-two\n" +
		"-----BEGIN PRIVATE KEY-----\nopaque-key-material\n-----END PRIVATE KEY-----\n" +
		"url=https://name:password@example.test/path key=ghp_abcdefghijklmnopqrstuv\n"
	sink.readAudit(strings.NewReader(text), int64(len(text)))
	sink.finishAudit()
	for _, secret := range []string{"fake-env-credential-1234", "short-secret", `\"x\"`, "tiny", "private-grant-body", "arbitrary-grant-material", "grant-line-one", "grant-line-two", "opaque-key-material", "name:password", "ghp_abcdefghijklmnopqrstuv"} {
		if strings.Contains(out.String(), secret) {
			t.Fatalf("secret %q persisted", secret)
		}
	}
	if !strings.Contains(out.String(), "/work/read.go") {
		t.Fatal("safe path lost")
	}
	lifecycleRecords(t, out.String())
}

func TestLifecycleAuditCapsRecordExactSourceLoss(t *testing.T) {
	var out bytes.Buffer
	sink := lifecycleTestSink(t, &out)
	sink.limit = 4096
	line := strings.Repeat("a", 1000) + "\n"
	text := strings.Repeat(line, 20)
	sink.readAudit(strings.NewReader(text), int64(len(text)))
	sink.finishAudit()
	sink.finishAudit()
	if int64(out.Len()) > sink.limit {
		t.Fatalf("cap exceeded: %d", out.Len())
	}
	var kept, dropped int64
	for _, record := range lifecycleRecords(t, out.String()) {
		switch record["type"] {
		case "leash_audit":
			kept += int64(len(line))
		case "truncation":
			dropped += int64(record["bytes_dropped"].(float64))
			if record["location"] != "audit_export" {
				t.Fatal("loss location missing")
			}
		}
	}
	if dropped == 0 || kept+dropped != int64(len(text)) {
		t.Fatalf("accounting: kept=%d dropped=%d input=%d", kept, dropped, len(text))
	}
}

func TestLifecycleAuditScrubsCredentialsAcrossReadFragments(t *testing.T) {
	var out bytes.Buffer
	t.Setenv("GITEA_TOKEN", "fragment-spanning-secret-1234")
	sink := lifecycleTestSink(t, &out)
	text := strings.Repeat("a", (64<<10)-5) + "fragment-spanning-secret-1234\n"
	sink.readAudit(strings.NewReader(text), int64(len(text)))
	sink.finishAudit()
	if strings.Contains(out.String(), "fragment-spanning") || !strings.Contains(out.String(), lifecycleRedacted) {
		t.Fatal("fragmented secret was not redacted")
	}
	if len(lifecycleRecords(t, out.String())) != 2 {
		t.Fatal("audit record split")
	}
}

func TestLifecycleAuditWithholdsIncompleteAndOversizedSecrets(t *testing.T) {
	for _, text := range []string{"Authorization: Bearer partial", strings.Repeat("s", lifecycleMaxLine+1) + "\nsecret-continuation\n"} {
		var out bytes.Buffer
		sink := lifecycleTestSink(t, &out)
		sink.readAudit(strings.NewReader(text), int64(len(text)))
		sink.finishAudit()
		sink.finishAudit()
		if strings.Contains(out.String(), "partial") || strings.Contains(out.String(), "secret-continuation") {
			t.Fatal("partial secret exported")
		}
		records := lifecycleRecords(t, out.String())
		if len(records) < 2 || records[len(records)-2]["type"] != "truncation" || records[len(records)-1]["status"] != "incomplete" {
			t.Fatal("missing loss")
		}
	}
}

func TestLifecycleAuditRefusesSymlinkWithoutChangingExit(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "private")
	if err := os.WriteFile(outside, []byte("untrusted-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "events.log")); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	r := &runner{cfg: config{workDir: root, workDirIsTemp: true, logDir: root}, lifecycleTelemetry: lifecycleTestSink(t, &out)}
	err := r.finishLifecycle(context.Background(), 37, nil)
	exit, ok := err.(*ExitCodeError)
	if !ok || exit.code != 37 {
		t.Fatalf("exit changed: %v", err)
	}
	if strings.Contains(out.String(), "untrusted-secret") || !strings.Contains(out.String(), "audit_source_unavailable") {
		t.Fatal("unsafe source used or not reported")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("unrelated file removed")
	}
}

func TestLifecycleAuditUnavailableAndFullSinkPreserveSuccess(t *testing.T) {
	out := &lifecycleFailWriter{}
	r := &runner{cfg: config{workDir: t.TempDir(), workDirIsTemp: true}, lifecycleTelemetry: lifecycleTestSink(t, out)}
	if err := r.finishLifecycle(context.Background(), 0, nil); err != nil {
		t.Fatalf("telemetry failed run: %v", err)
	}
}

func TestLifecyclePathPrivacyAndInvalidSettings(t *testing.T) {
	t.Setenv("LEASH_TELEMETRY_PRESERVE_HOST_PATHS", "false")
	r, err := newLifecycleRedactor("")
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	if strings.Contains(r.text(home+"/source.go"), home) {
		t.Fatal("host path retained")
	}
	for _, extra := range []string{"{", strings.Repeat("a", 65537)} {
		if _, err := newLifecycleRedactor(extra); err == nil {
			t.Fatal("invalid explicit secret list accepted")
		}
	}
	t.Setenv("LEASH_TELEMETRY_MAX_FILE_BYTES", "10")
	if _, err := newLifecycleTelemetry(&bytes.Buffer{}, ""); err == nil {
		t.Fatal("invalid cap accepted")
	}
}
