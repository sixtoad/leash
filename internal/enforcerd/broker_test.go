//go:build unix

package enforcerd

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const brokerWorkload = "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/user.slice/docker-w.scope"

// shortTempDir is a 0700 directory with a path short enough for a unix socket.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "lb-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// fakeDaemon answers every request line with a status result.
func fakeDaemon(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(shortTempDir(t), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					_, _ = c.Write([]byte(`{"v":1,"type":"result","ok":true,"status":{"version":"fake","protocol":1,"bpfLSM":"active","uid":1000}}` + "\n"))
				}
			}(c)
		}
	}()
	return sock
}

func startTestBroker(t *testing.T, peerCgroup string, peerUID int) (*Broker, string) {
	t.Helper()
	dir := shortTempDir(t)
	b, err := StartBroker(BrokerConfig{
		Dir:          dir,
		DaemonSocket: fakeDaemon(t),
		Workload:     brokerWorkload,
		UID:          1000,
		PeerCred:     func(*net.UnixConn) (int, int, error) { return peerUID, 4242, nil },
		ProcCgroup: func(int) ([]byte, error) {
			return []byte("0::" + strings.TrimPrefix(peerCgroup, CgroupRoot) + "\n"), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b, b.Socket()
}

func TestBrokerHandsOverOneDaemonConnection(t *testing.T) {
	b, sock := startTestBroker(t, "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/user.slice/docker-leash.scope", 1000)
	st, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("broker socket mode = %v", st.Mode().Perm())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := DialBroker(ctx, sock, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	status, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.Version != "fake" {
		t.Fatalf("status over the handed-over connection = %+v", status)
	}
	if !b.Served() {
		t.Fatal("broker does not report the handover")
	}
	// Single use: the broker stopped listening and removed its socket.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(sock); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("broker socket still present after the handover")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := DialBroker(ctx, sock, nil); err == nil {
		t.Fatal("a second connection must not be served")
	}
}

func TestBrokerRefusesTheWorkload(t *testing.T) {
	for _, cg := range []string{brokerWorkload, brokerWorkload + "/sub"} {
		b, sock := startTestBroker(t, cg, 1000)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := DialBroker(ctx, sock, nil)
		cancel()
		if err == nil || !strings.Contains(err.Error(), "inside the governed workload") {
			t.Fatalf("%s: err = %v", cg, err)
		}
		if b.Served() {
			t.Fatal("workload was served")
		}
		// A refusal does not use up the broker.
		if _, err := os.Stat(sock); err != nil {
			t.Fatalf("broker stopped after a refusal: %v", err)
		}
	}
}

func TestBrokerRefusesAnotherUID(t *testing.T) {
	b, sock := startTestBroker(t, "/sys/fs/cgroup/user.slice/user-1001.slice/session-1.scope", 1001)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := DialBroker(ctx, sock, nil)
	if err == nil || !strings.Contains(err.Error(), "uid 1001") {
		t.Fatalf("err = %v", err)
	}
	if b.Served() {
		t.Fatal("another uid was served")
	}
}

func TestBrokerReportsAnUnreachableDaemon(t *testing.T) {
	dir := shortTempDir(t)
	b, err := StartBroker(BrokerConfig{
		Dir:          dir,
		DaemonSocket: filepath.Join(dir, "missing.sock"),
		Workload:     brokerWorkload,
		UID:          1000,
		PeerCred:     func(*net.UnixConn) (int, int, error) { return 1000, 4242, nil },
		ProcCgroup:   func(int) ([]byte, error) { return []byte("0::/user.slice/x.scope\n"), nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = DialBroker(ctx, b.Socket(), nil)
	if err == nil || !strings.Contains(err.Error(), "sudo leash daemon install") {
		t.Fatalf("err = %v", err)
	}
}

func TestBrokerNeedsAPrivateDirectory(t *testing.T) {
	dir := shortTempDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := StartBroker(BrokerConfig{Dir: dir, DaemonSocket: "/x", Workload: brokerWorkload}); err == nil {
		t.Fatal("a broker in a shared directory must be refused")
	}
}
