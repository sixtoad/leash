package runner

import (
	"regexp"
	"strings"
)

// Embedded log prose is not necessarily a complete JSON value.
var lifecycleEscapedCredential = regexp.MustCompile(`(?i)\b[\w.-]*(?:token|secret|password|passwd|api[_-]?key|` +
	`credential|grant|authorization|cookie)[\w.-]*(\\+)(["'])\s*[:=]\s*`)

func redactLifecycleEscapedCredentials(text string) string {
	// Every escaped credential match requires a literal backslash.
	if !strings.ContainsRune(text, '\\') {
		return text
	}
	matches := lifecycleEscapedCredential.FindAllStringSubmatchIndex(text, -1)
	if len(matches) == 0 {
		return text
	}
	var clean strings.Builder
	clean.Grow(len(text))
	cursor := 0
	for _, m := range matches {
		if m[0] < cursor {
			continue
		}
		clean.WriteString(text[cursor:m[1]])
		clean.WriteString(lifecycleRedacted)
		cursor = lifecycleEscapedValueEnd(text, m)
	}
	clean.WriteString(text[cursor:])
	return clean.String()
}

func lifecycleEscapedValueEnd(text string, match []int) int {
	start, escapes, quote := match[1], match[3]-match[2], text[match[4]]
	// JSON escaping produces 1, 3, 7, or 15 slashes at the supported depths.
	if escapes > 15 || escapes&(escapes+1) != 0 {
		return len(text)
	}
	delimiter := strings.Repeat(`\`, escapes) + string(quote)
	if !strings.HasPrefix(text[start:], delimiter) {
		return len(text)
	}
	for j := start + len(delimiter); j < len(text); j++ {
		if text[j] == quote && lifecyclePrecedingSlashes(text, j)%(2*(escapes+1)) == escapes {
			return j + 1
		}
	}
	return len(text)
}

func lifecyclePrecedingSlashes(text string, end int) int {
	slashes := 0
	for k := end - 1; k >= 0 && text[k] == '\\'; k-- {
		slashes++
	}
	return slashes
}
