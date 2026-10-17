//go:build darwin

package darwind

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func fakeLsof(t *testing.T, output string) {
	t.Helper()
	script := filepath.Join(t.TempDir(), "lsof")
	body := "#!/bin/sh\ncat <<'EOF'\n" + output + "EOF\nexit 1\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := lsofPath
	lsofPath = script
	t.Cleanup(func() { lsofPath = orig })
}

func loopbackPair(t *testing.T) (server net.Conn, clientPort int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	server, err = ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { server.Close() })
	return server, client.LocalAddr().(*net.TCPAddr).Port
}

func fakeParents(t *testing.T, parents map[int]int) {
	t.Helper()
	orig := parentPID
	parentPID = func(pid int) (int, error) {
		if p, ok := parents[pid]; ok {
			return p, nil
		}
		return 1, nil
	}
	t.Cleanup(func() { parentPID = orig })
}

func TestControlConnFromLeashedProcessIsRefused(t *testing.T) {
	server, port := loopbackPair(t)
	srvPort := server.LocalAddr().(*net.TCPAddr).Port
	tracked := func() []int { return []int{4242} }
	// 4300 was forked by 4299, a child of the tracked 4242, before either
	// reached the daemon's tracked set.
	fakeParents(t, map[int]int{4300: 4299, 4299: 4242, 4242: 100, 5000: 100})
	daemonSide := fmt.Sprintf("p%d\nf7\nn127.0.0.1:%d->127.0.0.1:%d\n", os.Getpid(), srvPort, port)

	fakeLsof(t, daemonSide+fmt.Sprintf("p4242\nf3\nn127.0.0.1:%d->127.0.0.1:%d\n", port, srvPort))
	if allowControlConn("control", server, tracked) {
		t.Fatal("a leashed client was let through")
	}
	fakeLsof(t, daemonSide+fmt.Sprintf("p4300\nf3\nn127.0.0.1:%d->127.0.0.1:%d\n", port, srvPort))
	if allowControlConn("control", server, tracked) {
		t.Fatal("a descendant of a leashed process was let through")
	}
	fakeLsof(t, daemonSide+fmt.Sprintf("p5000\nf3\nn127.0.0.1:%d->127.0.0.1:%d\n", port, srvPort))
	if !allowControlConn("control", server, tracked) {
		t.Fatal("an unrelated client was refused")
	}
	// The leashed process holding another connection is not this client.
	fakeLsof(t, daemonSide+fmt.Sprintf("p4242\nf3\nn127.0.0.1:%d->127.0.0.1:%d\n", port+1, srvPort))
	if !allowControlConn("control", server, tracked) {
		t.Fatal("a client was confused with another connection")
	}

	// Nothing leashed: no lookup at all.
	lsofPath = "/nonexistent/lsof"
	if !allowControlConn("control", server, func() []int { return nil }) {
		t.Fatal("refused with no leashed process")
	}
	// A leashed workload exists but the client cannot be identified: refuse.
	if allowControlConn("control", server, tracked) {
		t.Fatal("unidentifiable client allowed while a workload is leashed")
	}
}
