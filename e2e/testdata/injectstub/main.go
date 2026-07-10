// Command injectstub is a generic --inject-service helper plugin used by the
// leash e2e suite. It knows nothing about any specific protocol (no D-Bus, no
// secret handling): it simply binds the socket leash tells it to bind, records
// the opaque config leash delivered, and serves a fixed sentinel so a client
// could prove reachability. leash's fail-closed readiness wait blocks until the
// socket file appears, so binding it is what lets the run proceed.
package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
)

// sentinel is written to every accepted connection so a client could prove the
// injected socket is reachable end-to-end.
const sentinel = "injectstub-ok\n"

func main() {
	// 1. The socket path leash asks us to bind travels via env (not argv). Without
	//    it there is nothing to do — exit non-zero so leash's fail-closed wait aborts.
	socket := os.Getenv("LEASH_INJECT_SOCKET")
	if socket == "" {
		fmt.Fprintln(os.Stderr, "injectstub: LEASH_INJECT_SOCKET is empty")
		os.Exit(1)
	}

	// 2. Read the opaque config leash delivered: prefer the 0600 file leash points
	//    us at (keeps the value out of `ps`), else fall back to an inline env value.
	//    leash never interprets this payload; neither do we.
	config := ""
	if cfgFile := os.Getenv("LEASH_INJECT_CONFIG_FILE"); cfgFile != "" {
		if data, err := os.ReadFile(cfgFile); err == nil {
			config = string(data)
		} else {
			fmt.Fprintf(os.Stderr, "injectstub: read LEASH_INJECT_CONFIG_FILE %q: %v\n", cfgFile, err)
		}
	} else {
		config = os.Getenv("LEASH_INJECT_CONFIG")
	}

	// 3. Record the received config so the test can confirm leash delivered the
	//    opaque payload end-to-end. Prefer an explicit marker path if leash's env
	//    reached us; otherwise derive one deterministically from the socket path
	//    (works even when leash spawns us via `runuser -- env` and scrubs the env).
	markerPath := os.Getenv("INJECTSTUB_MARKER")
	if markerPath == "" {
		markerPath = socket + ".cfg"
	}
	if err := os.WriteFile(markerPath, []byte(config), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "injectstub: write marker %q: %v\n", markerPath, err)
		os.Exit(1)
	}

	// 4. Bind the unix socket at the exact path leash gave us. Its appearance is the
	//    readiness signal leash waits for. Serve the sentinel on each connection.
	ln, err := net.Listen("unix", socket)
	if err != nil {
		fmt.Fprintf(os.Stderr, "injectstub: listen %q: %v\n", socket, err)
		os.Exit(1)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed during teardown
			}
			_, _ = conn.Write([]byte(sentinel))
			_ = conn.Close()
		}
	}()

	// 5. Idle until leash signals teardown (SIGINT), then exit cleanly. Stdlib only.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
