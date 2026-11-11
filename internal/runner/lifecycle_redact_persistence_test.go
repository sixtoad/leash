package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLifecycleEscapedAuditPersistence(t *testing.T) {
	var input strings.Builder
	for _, secret := range []string{`opaque\`, `opaque\\`, `opaque"quote\`, "opaque\ntrailing\\"} {
		encoded, _ := json.Marshal(map[string]string{"password": secret})
		for depth := 1; depth <= 4; depth++ {
			next, _ := json.Marshal(string(encoded))
			encoded = next[1 : len(next)-1]
			text := "prefix " + string(encoded) + " suffix"
			input.WriteString(text + "\n")
			structured, _ := json.Marshal(map[string]string{"content": text})
			input.Write(structured)
			input.WriteByte('\n')
		}
	}
	input.WriteString(`prefix {\"password\":\"opaque unterminated` + "\n")
	input.WriteString(`prefix {\"password\":opaque unquoted` + "\n")
	dir := t.TempDir()
	source := filepath.Join(dir, "events.log")
	if err := os.WriteFile(source, []byte(input.String()), 0600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "audit.ndjson")
	f, err := os.Create(output)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sink := lifecycleTestSink(t, f)
	r := runner{cfg: config{logDir: dir}, lifecycleTelemetry: sink}
	r.exportLifecycleAudit()
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "opaque") {
		t.Fatal("escaped credential reached persisted audit")
	}
	rows := lifecycleRecords(t, string(data))
	if len(rows) != 35 {
		t.Fatalf("expected 34 audit rows and footer, got %d", len(rows))
	}
	for i, row := range rows[:32] {
		content, _ := row["message"].(string)
		if payload, ok := row["payload"].(map[string]any); ok {
			content, _ = payload["content"].(string)
		}
		if !strings.HasPrefix(content, "prefix ") || !strings.HasSuffix(content, " suffix") {
			t.Fatalf("row %d context lost: %q", i, content)
		}
	}
	if rows[34]["status"] != "complete" {
		t.Fatal("redaction changed terminal delivery status")
	}
}
