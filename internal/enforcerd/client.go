package enforcerd

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// SocketPath returns the socket the client should use: $LEASH_ENFORCER_SOCKET
// or DefaultSocketPath.
func SocketPath() string {
	if p := strings.TrimSpace(os.Getenv(EnvSocket)); p != "" {
		return p
	}
	return DefaultSocketPath
}

// ErrSessionEnded is returned once the daemon reported the session over (or
// the connection dropped): enforcement is no longer known to be attached.
var ErrSessionEnded = errors.New("enforcer session ended")

// Client is one connection to the daemon. Requests are serialized; results
// come back in order. Event lines are delivered to OnEvent from the reader
// goroutine.
type Client struct {
	conn    io.ReadWriteCloser
	mu      sync.Mutex // serializes requests
	results chan Message
	ended   chan struct{}
	endErr  error
	endOnce sync.Once
	onEvent func(string)
	events  chan string
	timeout time.Duration
}

// Dial connects to the daemon at path. onEvent may be nil.
func Dial(ctx context.Context, path string, onEvent func(line string)) (*Client, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	return NewClient(conn, onEvent), nil
}

// NewClient wraps an established connection.
func NewClient(conn io.ReadWriteCloser, onEvent func(line string)) *Client {
	c := &Client{
		conn:    conn,
		results: make(chan Message, 1),
		ended:   make(chan struct{}),
		onEvent: onEvent,
		events:  make(chan string, 4096),
		timeout: 90 * time.Second,
	}
	go c.read()
	if onEvent != nil {
		go func() {
			for line := range c.events {
				onEvent(line)
			}
		}()
	}
	return c
}

func (c *Client) end(err error) {
	c.endOnce.Do(func() {
		c.endErr = err
		close(c.ended)
	})
}

func (c *Client) read() {
	sc := bufio.NewScanner(c.conn)
	sc.Buffer(make([]byte, 64*1024), MaxLineBytes)
	for sc.Scan() {
		var m Message
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			c.end(fmt.Errorf("%w: malformed message from the daemon: %v", ErrSessionEnded, err))
			_ = c.conn.Close()
			return
		}
		switch m.Type {
		case TypeEvent:
			// Never let a slow event sink stall the results.
			if c.onEvent != nil && m.Line != "" {
				select {
				case c.events <- m.Line:
				default:
				}
			}
		case TypeEnded:
			reason := m.Error
			if reason == "" {
				reason = "the session's worker exited"
			}
			c.end(fmt.Errorf("%w: %s", ErrSessionEnded, reason))
		case TypeResult:
			select {
			case c.results <- m:
			case <-c.ended:
				return
			}
		}
	}
	err := sc.Err()
	if err == nil {
		err = io.EOF
	}
	c.end(fmt.Errorf("%w: connection to the enforcer daemon closed (%v)", ErrSessionEnded, err))
}

// Ended is closed when the session ended or the connection dropped.
func (c *Client) Ended() <-chan struct{} { return c.ended }

// Err is why the session ended (nil while it has not).
func (c *Client) Err() error {
	select {
	case <-c.ended:
		return c.endErr
	default:
		return nil
	}
}

// Close closes the connection. It does not detach: an attached session stays
// enforced until it is detached or its cgroup goes away.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) do(req Request) (Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	req.V = ProtocolVersion
	data, err := json.Marshal(req)
	if err != nil {
		return Message{}, err
	}
	if len(data)+1 > MaxLineBytes {
		return Message{}, fmt.Errorf("request is %d bytes, more than the %d-byte limit", len(data), MaxLineBytes)
	}
	if _, err := c.conn.Write(append(data, '\n')); err != nil {
		// The daemon may have refused the connection and closed it before
		// reading the request: report its reason rather than the write error.
		select {
		case m := <-c.results:
			if !m.OK && m.Error != "" {
				return m, errors.New(m.Error)
			}
		case <-time.After(time.Second):
		}
		return Message{}, fmt.Errorf("send to the enforcer daemon: %w", err)
	}
	timer := time.NewTimer(c.timeout)
	defer timer.Stop()
	select {
	case m := <-c.results:
		if !m.OK {
			if m.Error == "" {
				m.Error = "refused"
			}
			return m, errors.New(m.Error)
		}
		return m, nil
	case <-c.ended:
		return Message{}, c.endErr
	case <-timer.C:
		return Message{}, fmt.Errorf("no answer from the enforcer daemon within %s", c.timeout)
	}
}

// Status asks the daemon to describe itself.
func (c *Client) Status() (*Status, error) {
	m, err := c.do(Request{Op: OpStatus})
	if err != nil {
		return nil, err
	}
	if m.Status == nil {
		return nil, errors.New("the enforcer daemon sent no status")
	}
	return m.Status, nil
}

// Attach asks the daemon to enforce policy on cgroup. It returns once every
// eBPF LSM program attached (or with the reason it could not). The
// connection then carries the session: events arrive on OnEvent, and Ended
// closes if enforcement is lost.
func (c *Client) Attach(cgroup, policy string, hosts map[string][]string) (session string, programs int, err error) {
	m, err := c.do(Request{Op: OpAttach, Cgroup: cgroup, Policy: policy, Hosts: hosts})
	if err != nil {
		return "", 0, err
	}
	return m.Session, m.Programs, nil
}

// Update replaces the attached session's policy.
func (c *Client) Update(policy string, hosts map[string][]string) error {
	_, err := c.do(Request{Op: OpUpdate, Policy: policy, Hosts: hosts})
	return err
}

// Detach ends the session: the worker detaches its programs and exits.
func (c *Client) Detach() error {
	_, err := c.do(Request{Op: OpDetach})
	return err
}
