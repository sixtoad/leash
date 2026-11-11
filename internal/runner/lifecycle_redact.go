package runner

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

const lifecycleRedacted = "[REDACTED]"

// Patterns mirror BME #415's runtime scrubber, including credential URL userinfo
// (Go's RE2 uses a captured prefix instead of JavaScript lookbehind).
var lifecycleSecretName = regexp.MustCompile(`(?i)(^|_)(TOKEN|SECRET|PASSWORD|PASSWD|PASS|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|KEY|PAT|SESSION|CREDENTIALS?|COOKIE|AUTH)(_|$)|OAUTH|APIKEY|authorization|grant`)
var lifecycleCamel = regexp.MustCompile(`([a-z0-9])([A-Z])`)
var lifecyclePatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{8,}`), regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`\bgh[opsur]_[A-Za-z0-9]{20,}`), regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}`),
	regexp.MustCompile(`\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*`), regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}`),
	regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]+`),
	regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}`), regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}`),
	regexp.MustCompile(`(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*`),
	regexp.MustCompile(`(?i)\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*:\s*[^\r\n]+`),
	// Grant contents are opaque capability material: withhold the remainder.
	regexp.MustCompile(`(?i)\b(?:grant|credentials?)["']?\s*[:=]\s*.*`),
}
var lifecycleAssignment = regexp.MustCompile(`(?i)\b([\w.-]*(?:token|secret|password|passwd|api[_-]?key|credential|authorization|cookie)[\w.-]*["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|[^\s,;}]+)`)
var lifecycleUserinfo = regexp.MustCompile(`(://)[^\s/:@]+:[^\s/@]+@`)

type lifecycleRedactor struct{ secrets, paths []string }

func newLifecycleRedactor(extra string) (*lifecycleRedactor, error) {
	r := &lifecycleRedactor{}
	if len(extra) > 64<<10 {
		return nil, fmt.Errorf("secret list too large")
	}
	if extra != "" {
		if err := json.Unmarshal([]byte(extra), &r.secrets); err != nil || len(r.secrets) > 256 {
			return nil, fmt.Errorf("invalid secret list")
		}
	}
	for _, pair := range os.Environ() {
		key, value, _ := strings.Cut(pair, "=")
		if lifecycleSecretName.MatchString(key) && len(value) >= 8 {
			r.secrets = append(r.secrets, value)
		}
	}
	// Include escaped variants because audit entries may contain JSON or quoted argv.
	for _, secret := range append([]string(nil), r.secrets...) {
		encoded, _ := json.Marshal(secret)
		r.secrets = append(r.secrets, string(encoded[1:len(encoded)-1]))
		if strings.ContainsAny(secret, "\r\n") {
			r.secrets = append(r.secrets, strings.FieldsFunc(secret, func(c rune) bool { return c == '\r' || c == '\n' })...)
		}
	}
	sort.Slice(r.secrets, func(i, j int) bool { return len(r.secrets[i]) > len(r.secrets[j]) })
	if value := os.Getenv("LEASH_TELEMETRY_PRESERVE_HOST_PATHS"); value == "false" || value == "0" {
		home, _ := os.UserHomeDir()
		cwd, _ := os.Getwd()
		r.paths = []string{home, cwd, os.TempDir()}
		sort.Slice(r.paths, func(i, j int) bool { return len(r.paths[i]) > len(r.paths[j]) })
	}
	return r, nil
}

func (r *lifecycleRedactor) text(text string) string {
	text = redactLifecycleEscapedCredentials(text)
	for _, secret := range r.secrets {
		if secret != "" {
			text = strings.ReplaceAll(text, secret, lifecycleRedacted)
		}
	}
	for _, pattern := range lifecyclePatterns {
		text = pattern.ReplaceAllString(text, lifecycleRedacted)
	}
	text = lifecycleUserinfo.ReplaceAllString(text, "${1}"+lifecycleRedacted+"@")
	text = lifecycleAssignment.ReplaceAllString(text, "${1}"+lifecycleRedacted)
	for _, path := range r.paths {
		if len(path) > 1 {
			text = strings.ReplaceAll(text, path, "${HOST_PATH}")
		}
	}
	return text
}

func (r *lifecycleRedactor) scrub(value any) any {
	switch value := value.(type) {
	case string:
		return r.text(value)
	case []any:
		for i := range value {
			value[i] = r.scrub(value[i])
		}
	case map[string]any:
		result := make(map[string]any, len(value))
		for key, item := range value {
			name := lifecycleCamel.ReplaceAllString(key, "${1}_${2}")
			if lifecycleSecretName.MatchString(strings.ReplaceAll(name, "-", "_")) {
				result[r.text(key)] = lifecycleRedacted
			} else {
				result[r.text(key)] = r.scrub(item)
			}
		}
		return result
	}
	return value
}
