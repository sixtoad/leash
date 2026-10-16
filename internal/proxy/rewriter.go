package proxy

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/strongdm/leash/internal/lsm"
)

// HeaderRewriteRule represents a single header rewrite rule
type HeaderRewriteRule struct {
	Host   string
	Header string
	Value  string
}

// String returns the canonical string representation of a HeaderRewriteRule
func (hr *HeaderRewriteRule) String() string {
	return fmt.Sprintf("allow http.rewrite %s header:%s:%s", hr.Host, hr.Header, hr.Value)
}

// HeaderRewriter manages header rewriting rules
type HeaderRewriter struct {
	rules        []HeaderRewriteRule
	mutex        sync.RWMutex
	sharedLogger *lsm.SharedLogger
}

func NewHeaderRewriter() *HeaderRewriter {
	return &HeaderRewriter{
		rules: make([]HeaderRewriteRule, 0),
	}
}

// SetSharedLogger sets the shared logger for event logging
func (hr *HeaderRewriter) SetSharedLogger(logger *lsm.SharedLogger) {
	hr.mutex.Lock()
	defer hr.mutex.Unlock()
	hr.sharedLogger = logger
}

func (hr *HeaderRewriter) LoadRulesFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		// If file doesn't exist, just continue with no rules
		if os.IsNotExist(err) {
			log.Printf("Header rewrite config file %s not found, continuing without header rewriting", filename)
			return nil
		}
		return fmt.Errorf("failed to open config file %s: %w", filename, err)
	}
	defer file.Close()

	hr.mutex.Lock()
	defer hr.mutex.Unlock()

	hr.rules = make([]HeaderRewriteRule, 0)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) != 3 {
			log.Printf("Warning: Invalid rule format at line %d: %s (expected host:header:value)", lineNum, line)
			continue
		}

		rule := HeaderRewriteRule{
			Host:   strings.TrimSpace(parts[0]),
			Header: strings.TrimSpace(parts[1]),
			Value:  strings.TrimSpace(parts[2]),
		}

		if rule.Host == "" || rule.Header == "" {
			log.Printf("Warning: Empty host or header at line %d: %s", lineNum, line)
			continue
		}

		hr.rules = append(hr.rules, rule)
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading config file: %w", err)
	}

	return nil
}

// SetRules replaces the current rule set atomically.
func (hr *HeaderRewriter) SetRules(rules []HeaderRewriteRule) {
	hr.mutex.Lock()
	defer hr.mutex.Unlock()

	// Copy to avoid external mutation
	newRules := make([]HeaderRewriteRule, len(rules))
	copy(newRules, rules)
	hr.rules = newRules

}

// ApplyRules modifies the request headers based on the loaded rules, matching
// on the request's own Host. The proxy request loops use ApplyRulesForHost
// with the connection's verified host instead (issue #149); this remains for
// callers that have already bound req.Host to the upstream they forward to.
func (hr *HeaderRewriter) ApplyRules(req *http.Request) {
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	hr.ApplyRulesForHost(req, host)
}

// ApplyRulesForHost applies the rules whose host matches host. host must be
// the host the request is actually forwarded to, not a client-supplied
// header. Matching ignores a port, case, IPv6 brackets and a trailing dot.
func (hr *HeaderRewriter) ApplyRulesForHost(req *http.Request, host string) {
	hr.mutex.RLock()
	defer hr.mutex.RUnlock()

	if len(hr.rules) == 0 {
		log.Printf("HeaderRewriter: No rules to apply")
		return
	}

	// Remove port if present
	if hostWithoutPort, _, err := net.SplitHostPort(host); err == nil {
		host = hostWithoutPort
	}
	host = normalizeAuthorityHost(host)
	if host == "" {
		return
	}

	for _, rule := range hr.rules {
		if normalizeAuthorityHost(rule.Host) == host {
			// always rewrite the header, even if it's empty
			oldValuePresent := headerValuePresent(req.Header, rule.Header)
			req.Header.Set(rule.Header, rule.Value)

			// Log to shared event log
			if hr.sharedLogger != nil {
				timestamp := time.Now().Format(time.RFC3339)
				logEntry := fmt.Sprintf("time=%s event=http.rewrite addr=\"%s\" header=\"%s\" from_present=%t to_present=%t decision=allowed",
					timestamp, host, rule.Header, oldValuePresent, strings.TrimSpace(rule.Value) != "")
				_ = hr.sharedLogger.Write(logEntry)
			}
		}
	}
}

// HasRulesForHost reports whether any rewrite rule targets host. It uses the
// same matching as ApplyRulesForHost (port stripped, normalizeAuthorityHost on
// both sides) so the proxy can decide, per TLS connection, whether requests
// to host must be inspected.
func (hr *HeaderRewriter) HasRulesForHost(host string) bool {
	if hr == nil {
		return false
	}
	if hostWithoutPort, _, err := net.SplitHostPort(host); err == nil {
		host = hostWithoutPort
	}
	host = normalizeAuthorityHost(host)
	if host == "" {
		return false
	}
	hr.mutex.RLock()
	defer hr.mutex.RUnlock()
	for _, rule := range hr.rules {
		if normalizeAuthorityHost(rule.Host) == host {
			return true
		}
	}
	return false
}
