package proxy

import (
	"bufio"
	"io"
	"net"
	"testing"
)

func TestParseProxyProtocolV1Line(t *testing.T) {
	cases := []struct {
		name    string
		line    string
		want    string
		wantErr bool
	}{
		{"tcp4", "PROXY TCP4 10.0.0.1 93.184.216.34 51000 443", "93.184.216.34:443", false},
		{"tcp6", "PROXY TCP6 ::1 2606:2800:220:1:248:1893:25c8:1946 51000 443", "[2606:2800:220:1:248:1893:25c8:1946]:443", false},
		{"missing fields", "PROXY TCP4 10.0.0.1 93.184.216.34 51000", "", true},
		{"bad prefix", "NOTPROXY TCP4 10.0.0.1 93.184.216.34 51000 443", "", true},
		{"bad family", "PROXY TCP5 10.0.0.1 93.184.216.34 51000 443", "", true},
		{"hostname dst", "PROXY TCP4 10.0.0.1 example.com 51000 443", "example.com:443", false},
		{"port too large", "PROXY TCP4 10.0.0.1 93.184.216.34 51000 70000", "", true},
		{"port zero", "PROXY TCP4 10.0.0.1 93.184.216.34 51000 0", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseProxyProtocolV1Line(tc.line)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q, got %q", tc.line, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// The header read must stop exactly at the CRLF so the client's first application
// bytes remain unread for the downstream HTTP/TLS classifier.
func TestReadProxyProtocolV1DestStopsAtCRLF(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	header := "PROXY TCP4 10.0.0.1 93.184.216.34 51000 443\r\n"
	appData := []byte("GET / HTTP/1.1\r\n")

	go func() {
		_, _ = client.Write([]byte(header))
		_, _ = client.Write(appData)
	}()

	rd := bufio.NewReader(server)
	dest, err := readProxyProtocolV1Dest(rd)
	if err != nil {
		t.Fatalf("readProxyProtocolV1Dest: %v", err)
	}
	if want := "93.184.216.34:443"; dest != want {
		t.Fatalf("dest = %q, want %q", dest, want)
	}

	// Read app bytes from the SAME buffered reader — the buffer may have pulled
	// past the header, so reading the raw conn here would lose data.
	buf := make([]byte, len(appData))
	if _, err := io.ReadFull(rd, buf); err != nil {
		t.Fatalf("reading app data after header: %v", err)
	}
	if string(buf) != string(appData) {
		t.Fatalf("app data = %q, want %q (header read over-consumed)", buf, appData)
	}
}

func TestReadProxyProtocolV1DestMissingCRLF(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 10.0.0.1 93.184.216.34 51000 443"))
		client.Close()
	}()

	if _, err := readProxyProtocolV1Dest(bufio.NewReader(server)); err == nil {
		t.Fatal("expected error when header lacks CRLF")
	}
}
