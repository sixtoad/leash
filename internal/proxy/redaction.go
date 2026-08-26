package proxy

import (
	"net/http"
	"strings"
)

func headerValuePresent(header http.Header, name string) bool {
	for _, value := range header.Values(name) {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}
