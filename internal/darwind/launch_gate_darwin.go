//go:build darwin

package darwind

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/strongdm/leash/internal/macext"
)

const (
	execDarwinHealthURL = "http://127.0.0.1:18080/health/darwin"
	// enforcementReadyTimeout covers extensions reconnecting to a daemon that
	// was just started (their websocket backoff) and applying its tables.
	enforcementReadyTimeout = 60 * time.Second
	// trackedTimeout is how long leashcli may wait for the ES extension to
	// report it as tracked before leash gives up on running the command.
	trackedTimeout = 15 * time.Second
	// leashcliStartFD is where leashcli reads the go-ahead (fd 3: the first
	// of cmd.ExtraFiles). It runs the command only after reading "go".
	leashcliStartFD = "3"
)

func readDarwinHealth() (macext.DaemonHealth, error) {
	var h macext.DaemonHealth
	resp, err := execHTTPClient.Get(execDarwinHealthURL)
	if err != nil {
		return h, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return h, fmt.Errorf("%s: %s", execDarwinHealthURL, resp.Status)
	}
	err = json.NewDecoder(resp.Body).Decode(&h)
	return h, err
}

// waitForEnforcement polls the daemon until enforcementGaps is empty.
func waitForEnforcement(timeout time.Duration) error {
	start := time.Now()
	announced := false
	var gaps []string
	for {
		h, err := readDarwinHealth()
		if err != nil {
			gaps = []string{fmt.Sprintf("cannot read the daemon's enforcement state: %v", err)}
		} else {
			gaps = enforcementGaps(h)
		}
		if len(gaps) == 0 {
			return nil
		}
		if time.Since(start) > timeout {
			return enforcementGateError(gaps, timeout.String())
		}
		if !announced && time.Since(start) > 2*time.Second {
			fmt.Fprintf(os.Stderr, "leash: waiting for macOS enforcement (%s)\n", strings.Join(gaps, "; "))
			announced = true
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// runLeashcli starts leashcli, waits until the Endpoint Security extension
// tracks it, and only then lets it run the command. leashcli itself would
// race (it used to sleep half a second and hope the extension had switched
// to AUTH mode), and a leashcli the extension never tracks, for example one
// started without a terminal by an older extension, would run the command
// with no enforcement at all.
func runLeashcli(cmd *exec.Cmd) error {
	r, w, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("leashcli start pipe: %w", err)
	}
	cmd.ExtraFiles = []*os.File{r}
	cmd.Env = withEnv(cmd.Env, "LEASH_START_FD", leashcliStartFD)
	if err := cmd.Start(); err != nil {
		r.Close()
		w.Close()
		return err
	}
	r.Close()

	pid := cmd.Process.Pid
	deadline := time.Now().Add(trackedTimeout)
	for {
		h, err := readDarwinHealth()
		if err == nil && gateTracked(h, pid) {
			if len(enforcementGaps(h)) == 0 {
				break
			}
		}
		if time.Now().After(deadline) {
			w.Close() // leashcli reads EOF and exits without running the command
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			reason := "the Endpoint Security extension did not report it as tracked"
			if err == nil {
				if gaps := enforcementGaps(h); len(gaps) > 0 {
					reason = strings.Join(gaps, "; ")
				}
			} else {
				reason = err.Error()
			}
			return fmt.Errorf("leash will not run the command unenforced: leashcli (pid %d) was not confirmed as leashed within %s (%s)", pid, trackedTimeout, reason)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := io.WriteString(w, "go\n"); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		w.Close()
		return fmt.Errorf("leashcli start pipe: %w", err)
	}
	w.Close()
	return cmd.Wait()
}
