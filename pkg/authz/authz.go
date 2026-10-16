// Package authz is the client side of Leash's plugin authorization socket
// (#142): the wire types of protocol v1 and a small fail-closed client.
//
// A plugin spawned by `leash --inject-service ...,authz=<Namespaces>` finds
// its socket in LEASH_AUTHZ_SOCKET. Every decision is Cedar's own evaluation
// (cedar-go Authorize) through the same engine Leash enforces its policy
// with; this package only carries requests and answers.
//
// Fail closed: Check returns a Decision whose Allowed() is true only for a
// well-formed "allow" answer. Every error (no socket, timeout, malformed or
// mismatched reply, unsupported version) yields a deny together with the
// error.
//
// The package depends on the standard library only, so plugins outside the
// Leash module can import it without pulling in Leash internals.
package authz

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProtocolVersion is the wire protocol version this package speaks.
const ProtocolVersion = 1

// Environment variables Leash sets for an authz-enabled plugin.
const (
	EnvSocket   = "LEASH_AUTHZ_SOCKET"
	EnvPluginID = "LEASH_AUTHZ_PLUGIN_ID"
)

// Wire limits (the server enforces them; the client checks the request size
// up front so an oversized request fails locally).
const (
	MaxLineBytes     = 64 << 10
	MaxContextKeys   = 64
	MaxStringBytes   = 4 << 10
	MaxSetElements   = 256
	DefaultTimeout   = 2 * time.Second
	DecisionAllow    = "allow"
	DecisionDeny     = "deny"
	entityContextKey = "__entity"
)

// Reasons carried in Response.Reason. The list is append-only.
const (
	ReasonMatchedPermit       = "matched_permit"
	ReasonMatchedForbid       = "matched_forbid"
	ReasonDefaultAllow        = "default_allow"
	ReasonDefaultDeny         = "default_deny"
	ReasonUnsupportedAction   = "unsupported_action"
	ReasonInvalidRequest      = "invalid_request"
	ReasonNoPolicy            = "no_policy"
	ReasonNamespaceNotGranted = "namespace_not_granted"
	ReasonRateLimited         = "rate_limited"
	ReasonUnsupportedVersion  = "unsupported_version"
	// ReasonApprovalRequired is reserved for the per-request approval flow.
	ReasonApprovalRequired = "approval_required"
)

// EntityUID names a Cedar entity.
type EntityUID struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// UID builds an EntityUID.
func UID(typ, id string) EntityUID { return EntityUID{Type: typ, ID: id} }

// String renders the UID in Cedar syntax.
func (e EntityUID) String() string { return e.Type + "::" + strconv.Quote(e.ID) }

// Entity wraps an entity reference as a context value; it is encoded as
// {"__entity":{"type":..,"id":..}}.
type Entity EntityUID

// MarshalJSON encodes the Cedar JSON entity escape.
func (e Entity) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]EntityUID{entityContextKey: EntityUID(e)})
}

// Request is one authorization question. The principal is not part of the
// request: Leash sets it to Plugin::"<id>" from the socket the request
// arrived on.
type Request struct {
	V        int            `json:"v"`
	ID       string         `json:"id,omitempty"`
	Action   EntityUID      `json:"action"`
	Resource EntityUID      `json:"resource"`
	Context  map[string]any `json:"context,omitempty"`
}

// Response is Leash's answer.
type Response struct {
	V          int       `json:"v"`
	ID         string    `json:"id,omitempty"`
	Decision   string    `json:"decision"`
	Reason     string    `json:"reason,omitempty"`
	Policies   []string  `json:"policies,omitempty"`
	Rule       string    `json:"rule,omitempty"` // kept for compatibility; Leash leaves it empty (Policies names the deciding policies)
	Principal  EntityUID `json:"principal"`
	Generation uint64    `json:"generation,omitempty"`
	Error      string    `json:"error,omitempty"`
}

// Decision is the client-side view of a Response.
type Decision struct {
	Response
	// Err is set when no trustworthy answer was obtained; the decision is a
	// deny in that case.
	Err error
}

// Allowed reports whether Leash answered "allow". It is false on any error.
func (d Decision) Allowed() bool {
	return d.Err == nil && d.Response.Decision == DecisionAllow
}

// Client talks to one authz socket. It keeps one connection and serializes
// requests on it; it reconnects after an error. Safe for concurrent use.
type Client struct {
	path    string
	timeout time.Duration

	mu   sync.Mutex
	conn net.Conn
	rd   *bufio.Reader
	seq  uint64
}

// Option configures a Client.
type Option func(*Client)

// WithTimeout bounds each Check (connect + write + read). Default 2s.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// New returns a client for the socket at path. It does not connect yet.
func New(path string, opts ...Option) *Client {
	c := &Client{path: path, timeout: DefaultTimeout}
	for _, o := range opts {
		o(c)
	}
	return c
}

// ErrNotConfigured is returned by NewFromEnv when LEASH_AUTHZ_SOCKET is unset:
// the plugin was not granted the authz service and must treat every
// question as denied.
var ErrNotConfigured = errors.New("authz: " + EnvSocket + " is not set")

// NewFromEnv returns a client for LEASH_AUTHZ_SOCKET.
func NewFromEnv(opts ...Option) (*Client, error) {
	path := strings.TrimSpace(os.Getenv(EnvSocket))
	if path == "" {
		return nil, ErrNotConfigured
	}
	return New(path, opts...), nil
}

// Close drops the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropLocked()
}

func (c *Client) dropLocked() error {
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn, c.rd = nil, nil
	return err
}

func deny(req Request, err error) Decision {
	return Decision{Response: Response{V: ProtocolVersion, ID: req.ID, Decision: DecisionDeny}, Err: err}
}

// Check asks one question. The returned Decision is a deny whenever Err is
// set; callers should simply test Allowed().
func (c *Client) Check(ctx context.Context, req Request) Decision {
	if c == nil {
		return deny(req, ErrNotConfigured)
	}
	req.V = ProtocolVersion
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	if req.ID == "" {
		req.ID = strconv.FormatUint(c.seq, 10)
	}
	line, err := json.Marshal(req)
	if err != nil {
		return deny(req, fmt.Errorf("authz: encode request: %w", err))
	}
	if len(line)+1 > MaxLineBytes {
		return deny(req, fmt.Errorf("authz: request is %d bytes, over the %d-byte limit", len(line)+1, MaxLineBytes))
	}
	line = append(line, '\n')

	deadline := time.Now().Add(c.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	resp, err := c.roundTripLocked(ctx, line, deadline)
	if err != nil {
		_ = c.dropLocked()
		return deny(req, err)
	}
	if resp.V != ProtocolVersion {
		return Decision{Response: *resp, Err: fmt.Errorf("authz: server speaks protocol v%d, want v%d", resp.V, ProtocolVersion)}
	}
	if resp.ID != req.ID {
		_ = c.dropLocked()
		return deny(req, fmt.Errorf("authz: reply id %q does not match request id %q", resp.ID, req.ID))
	}
	switch resp.Decision {
	case DecisionAllow, DecisionDeny:
	default:
		return Decision{Response: *resp, Err: fmt.Errorf("authz: unknown decision %q", resp.Decision)}
	}
	return Decision{Response: *resp}
}

func (c *Client) roundTripLocked(ctx context.Context, line []byte, deadline time.Time) (*Response, error) {
	if c.conn == nil {
		dialer := net.Dialer{Deadline: deadline}
		conn, err := dialer.DialContext(ctx, "unix", c.path)
		if err != nil {
			return nil, fmt.Errorf("authz: connect %s: %w", c.path, err)
		}
		c.conn, c.rd = conn, bufio.NewReaderSize(conn, 4096)
	}
	if err := c.conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = c.conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()
	if _, err := c.conn.Write(line); err != nil {
		return nil, fmt.Errorf("authz: write: %w", err)
	}
	raw, err := readLine(c.rd, MaxLineBytes)
	if err != nil {
		return nil, fmt.Errorf("authz: read: %w", err)
	}
	var resp Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("authz: malformed reply: %w", err)
	}
	return &resp, nil
}

// ErrLineTooLong is returned when a protocol line exceeds MaxLineBytes.
var ErrLineTooLong = errors.New("authz: line exceeds the protocol limit")

// readLine reads one '\n'-terminated line of at most limit bytes (newline
// included) and returns it without the newline. Shared by client and server.
func readLine(rd *bufio.Reader, limit int) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := rd.ReadSlice('\n')
		buf = append(buf, chunk...)
		if len(buf) > limit {
			return nil, ErrLineTooLong
		}
		if err == nil {
			return buf[:len(buf)-1], nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

// ReadLine is readLine exported for the Leash server.
func ReadLine(rd *bufio.Reader, limit int) ([]byte, error) { return readLine(rd, limit) }
