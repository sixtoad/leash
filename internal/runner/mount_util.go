package runner

import (
	"fmt"
	"path/filepath"
	"strings"
)

func parseIDMapVolume(raw string) (idmapVolume, error) {
	parts := strings.Split(raw, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return idmapVolume{}, fmt.Errorf("invalid idmap volume %q; expected absolute src:dst[:ro]", raw)
	}
	host, target := filepath.Clean(strings.TrimSpace(parts[0])), filepath.Clean(strings.TrimSpace(parts[1]))
	if !filepath.IsAbs(host) || !filepath.IsAbs(target) {
		return idmapVolume{}, fmt.Errorf("invalid idmap volume %q; source and target must be absolute", raw)
	}
	mode := ""
	if len(parts) == 3 {
		mode = strings.TrimSpace(parts[2])
		if mode != "ro" && mode != "rw" {
			return idmapVolume{}, fmt.Errorf("invalid idmap volume %q; mode must be ro or rw", raw)
		}
	}
	return idmapVolume{raw: raw, host: host, target: target, mode: mode}, nil
}

func volumeContainerPath(volume string) string {
	parts := strings.Split(volume, ":")
	for i := len(parts) - 1; i >= 0; i-- {
		segment := strings.TrimSpace(parts[i])
		if strings.HasPrefix(segment, "/") {
			return segment
		}
	}
	return ""
}

func volumeHostContainer(volume string) (string, string, bool) {
	parts := strings.Split(volume, ":")
	if len(parts) < 2 {
		return "", "", false
	}
	host := strings.TrimSpace(parts[0])
	container := strings.TrimSpace(parts[1])
	if host == "" || container == "" {
		return "", "", false
	}
	return filepath.Clean(host), filepath.Clean(container), true
}
