package proxy

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/strongdm/leash/internal/lsm"
)

func TestLogRequestRedactsAuthorizationFromEverySink(t *testing.T) {
	tests := []struct {
		name         string
		auth         string
		responseCode int
		err          error
		decision     string
	}{
		{name: "allowed bearer", auth: "Bearer synthetic-bearer-sentinel-987654", responseCode: 200, decision: "allowed"},
		{name: "denied basic", auth: "Basic synthetic-basic-sentinel-987654", responseCode: 403, err: errors.New("policy denied"), decision: "denied"},
		{name: "forwarding error api key", auth: "ApiKey synthetic-api-key-sentinel-987654", err: errors.New("forward failed"), decision: "denied"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proxy, logPath, capture := newCapturingProxyLogger(t)
			authPresent := headerValuePresent(http.Header{"Authorization": []string{tt.auth}}, "Authorization")

			proxy.logRequest("https", "example.test", "443", "/v1", "", authPresent, tt.responseCode, tt.err)

			assertSecretAbsentFromLoggerSinks(t, logPath, capture, tt.auth)
			entry := onlyCapturedEntry(t, capture)
			if !strings.Contains(entry, " auth_present=true") {
				t.Fatalf("request log missing authorization presence metadata: %s", entry)
			}
			if strings.Contains(entry, " auth=") {
				t.Fatalf("request log retained legacy authorization value field: %s", entry)
			}
			if !strings.Contains(entry, "decision="+tt.decision) {
				t.Fatalf("request log changed decision metadata: %s", entry)
			}
		})
	}
}

func TestLogRequestOmitsAuthorizationPresenceForWhitespace(t *testing.T) {
	proxy, _, capture := newCapturingProxyLogger(t)

	proxy.logRequest("https", "example.test", "443", "/v1", "", false, 200, nil)

	entry := onlyCapturedEntry(t, capture)
	if strings.Contains(entry, "auth_present") || strings.Contains(entry, " auth=") {
		t.Fatalf("request log reported an empty authorization value: %s", entry)
	}
}

func TestHeaderRewriteRedactsValuesFromEverySink(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "authorization", header: "Authorization"},
		{name: "proxy authorization", header: "Proxy-Authorization"},
		{name: "cookie", header: "Cookie"},
		{name: "api key", header: "X-API-Key"},
		{name: "custom secret", header: "X-Leash-Auth"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logPath := filepath.Join(t.TempDir(), "events.log")
			logger, err := lsm.NewSharedLogger(logPath)
			if err != nil {
				t.Fatalf("create shared logger: %v", err)
			}
			t.Cleanup(func() { _ = logger.Close() })
			capture := &capturingBroadcaster{}
			logger.SetBroadcaster(capture)

			oldValue := "synthetic-old-value-sentinel-987654"
			newValue := "synthetic-new-value-sentinel-123456"
			rewriter := NewHeaderRewriter()
			rewriter.SetSharedLogger(logger)
			rewriter.SetRules([]HeaderRewriteRule{{Host: "example.test", Header: tt.header, Value: newValue}})
			req, err := httpRequestWithHeader(tt.header, oldValue)
			if err != nil {
				t.Fatalf("create request: %v", err)
			}

			rewriter.ApplyRules(req)

			if got := req.Header.Get(tt.header); got != newValue {
				t.Fatalf("rewrite changed forwarded value: got %q", got)
			}
			assertSecretAbsentFromLoggerSinks(t, logPath, capture, oldValue, newValue)
			entry := onlyCapturedEntry(t, capture)
			if !strings.Contains(entry, " from_present=true") || !strings.Contains(entry, " to_present=true") {
				t.Fatalf("rewrite log missing value presence metadata: %s", entry)
			}
			if strings.Contains(entry, " from=") || strings.Contains(entry, " to=") {
				t.Fatalf("rewrite log retained legacy value fields: %s", entry)
			}
		})
	}
}

func TestHeaderRewriteReportsEmptyValuesWithoutLoggingThem(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "events.log")
	logger, err := lsm.NewSharedLogger(logPath)
	if err != nil {
		t.Fatalf("create shared logger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	capture := &capturingBroadcaster{}
	logger.SetBroadcaster(capture)

	rewriter := NewHeaderRewriter()
	rewriter.SetSharedLogger(logger)
	rewriter.SetRules([]HeaderRewriteRule{{Host: "example.test", Header: "Authorization", Value: " \t "}})
	req, err := httpRequestWithHeader("Authorization", "")
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	rewriter.ApplyRules(req)

	entry := onlyCapturedEntry(t, capture)
	if !strings.Contains(entry, " from_present=false") || !strings.Contains(entry, " to_present=false") {
		t.Fatalf("rewrite log has incorrect empty-value metadata: %s", entry)
	}
}

func TestHeaderPresenceUsesEveryStoredValue(t *testing.T) {
	header := http.Header{"Authorization": []string{" \t ", "Bearer synthetic-multi-value-sentinel-987654"}}
	if !headerValuePresent(header, "Authorization") {
		t.Fatal("expected a populated later header value to report presence")
	}

	logPath := filepath.Join(t.TempDir(), "events.log")
	logger, err := lsm.NewSharedLogger(logPath)
	if err != nil {
		t.Fatalf("create shared logger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	capture := &capturingBroadcaster{}
	logger.SetBroadcaster(capture)
	rewriter := NewHeaderRewriter()
	rewriter.SetSharedLogger(logger)
	rewriter.SetRules([]HeaderRewriteRule{{Host: "example.test", Header: "Authorization", Value: "replacement"}})
	req, err := http.NewRequest("GET", "https://example.test/v1", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	req.Host = "example.test"
	req.Header = header.Clone()

	rewriter.ApplyRules(req)

	entry := onlyCapturedEntry(t, capture)
	if !strings.Contains(entry, " from_present=true") {
		t.Fatalf("rewrite log ignored a populated later header value: %s", entry)
	}
	assertSecretAbsentFromLoggerSinks(t, logPath, capture, header.Values("Authorization")...)
}

func newCapturingProxyLogger(t *testing.T) (*MITMProxy, string, *capturingBroadcaster) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "events.log")
	logger, err := lsm.NewSharedLogger(logPath)
	if err != nil {
		t.Fatalf("create shared logger: %v", err)
	}
	t.Cleanup(func() { _ = logger.Close() })
	capture := &capturingBroadcaster{}
	logger.SetBroadcaster(capture)
	return &MITMProxy{sharedLogger: logger}, logPath, capture
}

func httpRequestWithHeader(header, value string) (*http.Request, error) {
	req, err := http.NewRequest("GET", "https://example.test/v1", nil)
	if err != nil {
		return nil, err
	}
	req.Host = "example.test"
	if value != "" {
		req.Header.Set(header, value)
	}
	return req, nil
}

func onlyCapturedEntry(t *testing.T, capture *capturingBroadcaster) string {
	t.Helper()
	entries := capture.all()
	if len(entries) != 1 {
		t.Fatalf("expected one captured entry, got %d", len(entries))
	}
	return entries[0]
}

func assertSecretAbsentFromLoggerSinks(t *testing.T, logPath string, capture *capturingBroadcaster, secrets ...string) {
	t.Helper()
	fileBytes, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read event log: %v", err)
	}
	sinks := []string{string(fileBytes), strings.Join(capture.all(), "\n")}
	for _, sink := range sinks {
		for _, secret := range secrets {
			trimmed := strings.TrimSpace(secret)
			if trimmed == "" {
				continue
			}
			fragments := secretFragments(trimmed, 12)
			for _, fragment := range fragments {
				if strings.Contains(sink, fragment) {
					t.Fatalf("logger sink contains synthetic secret material")
				}
			}
		}
	}
}

func secretFragments(secret string, width int) []string {
	if width <= 0 || len(secret) <= width {
		return []string{secret}
	}
	fragments := make([]string, 0, len(secret)-width+2)
	fragments = append(fragments, secret)
	for start := 0; start+width <= len(secret); start++ {
		fragments = append(fragments, secret[start:start+width])
	}
	return fragments
}
