package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/strongdm/leash/internal/networkpin"
)

// Pin only Docker's own hosts file. An ancestor mount can shadow it too, and
// container:<id> networking shares another container's file, not this run's.
func validateNetworkPinTarget(raw string) error {
	var target struct {
		HostsPath  string
		HostConfig struct{ NetworkMode string }
		Mounts     []struct{ Destination string }
	}
	if err := json.Unmarshal([]byte(raw), &target); err != nil {
		return fmt.Errorf("inspect network pin target: %w", err)
	}
	if target.HostsPath == "" {
		return fmt.Errorf("network host pinning requires Docker's managed hosts file")
	}
	if strings.HasPrefix(target.HostConfig.NetworkMode, "container:") {
		return fmt.Errorf("network host pinning does not support container-shared network mode")
	}
	for _, mount := range target.Mounts {
		dest := filepath.Clean(mount.Destination)
		if dest == "/" || dest == "/etc" || dest == "/etc/hosts" {
			return fmt.Errorf("network host pinning refuses mount shadowing /etc/hosts: %s", dest)
		}
	}
	return nil
}

func (r *runner) prepareNetworkPins(ctx context.Context) error {
	if len(r.opts.pinNetworkHosts) == 0 {
		return nil
	}
	if r.rt().Name() != "docker" {
		return fmt.Errorf("--pin-network-host requires Docker")
	}
	ctx, cancel := context.WithTimeout(ctx, networkpin.Timeout+2*time.Second)
	defer cancel()
	out, err := r.rt().Output(ctx, "inspect", "--format", `{"HostsPath":{{json .HostsPath}},"HostConfig":{"NetworkMode":{{json .HostConfig.NetworkMode}}},"Mounts":{{json .Mounts}}}`, r.cfg.targetContainer)
	if err != nil {
		return fmt.Errorf("inspect network pin target: %w", err)
	}
	if err = validateNetworkPinTarget(out); err != nil {
		return err
	}
	arch, err := r.detectImageArch(ctx)
	if err != nil {
		return err
	}
	helper := filepath.Join(leashPublicMount, fmt.Sprintf("leash-entry-linux-%s", arch))
	args := []string{"exec", "--user", "0", r.cfg.targetContainer, helper, "--pin-network-hosts"}
	args = append(args, r.opts.pinNetworkHosts...)
	cmd := r.rt().Cmd(ctx, args...)
	cmd.WaitDelay = time.Second
	var stdout, diagnostics pinOutputBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = io.MultiWriter(&diagnostics, r.logger.Writer())
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("pin network hosts before enforcement: %w: %s", err, strings.TrimSpace(diagnostics.String()))
	}
	out = stdout.String()

	var mappings []networkpin.Mapping
	if err = json.Unmarshal([]byte(out), &mappings); err != nil {
		return fmt.Errorf("invalid network host snapshot: %w", err)
	}
	encoded, err := json.Marshal(mappings)
	if err != nil {
		return err
	}
	r.logger.Printf("event=runner.network-hosts status=pinned snapshot=%s\n", encoded)
	return nil
}

// Bound both streams independently; resolver diagnostics must never become JSON.
type pinOutputBuffer struct{ buffer bytes.Buffer }

func (b *pinOutputBuffer) Len() int       { return b.buffer.Len() }
func (b *pinOutputBuffer) String() string { return b.buffer.String() }
func (b *pinOutputBuffer) Write(data []byte) (int, error) {
	if b.Len()+len(data) > 64*1024 {
		return 0, errors.New("network host helper output exceeds limit")
	}
	return b.buffer.Write(data)
}
