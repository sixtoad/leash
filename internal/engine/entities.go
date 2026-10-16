package engine

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/cedar-policy/cedar-go/types"
)

// Leash's entity hierarchy.
//
// Leash has no entity store: the hierarchy of a built-in resource is a pure
// function of the request, built here. It is what gives `resource in E` its
// meaning for Leash's resource types, and the kernel compiler
// (transpiler.CompileKernel) compiles exactly these relations into the
// kernel's prefix tables. Changing anything here changes enforcement: the
// parity tests pin it to the kernel's matchers.
//
// Files (request resource File::"<path>"; path is absolute):
//
//   - File::"p" is exactly the path p: it contains nothing else.
//   - FilePrefix::"q" contains every path q is a byte prefix of, q itself
//     included (FilePrefix::"/bin/rm" covers "/bin/rm" and "/bin/rmdir").
//     It is the strict form of a legacy File rule, whose kernel matching was
//     always by byte prefix.
//   - Dir::"d/" contains every path under d/ and, for file opens, the
//     directory d itself (opendir/stat of the root of a granted tree, #119).
//     Execs never target a directory, so ProcessExec has no self match.
//     Dir::"d" (no trailing slash) is the same directory as Dir::"d/".
//
// Hosts (request resource Host::"<name>", or Host::"<ip>" without a name):
//
//   - Host::"name" (case-insensitive, trailing dot ignored), Host::"*.zone"
//     for every proper label suffix of the name (label boundary: *.example.com
//     covers a.example.com, not example.com or evilexample.com), Host::"<ip>",
//     and Host::"*" (any host).
//   - With a known port, each of those also as Host::"<x>:<port>", plus
//     Host::"*:<port>" (any host on that port).
//
// MCP (request resource MCP::Tool::"<tool>", lowercased):
//
//   - MCP::Server::"<server>" (normalized: lowercased, scheme, path and port
//     stripped).

// fileParents returns every entity a file path is in (the path itself is
// the resource, so it is not listed). dirSelf adds the directory-self match
// of file opens.
func fileParents(path string, dirSelf bool) []types.EntityUID {
	out := make([]types.EntityUID, 0, 2*len(path)+4)
	for k := 1; k <= len(path); k++ {
		out = append(out, types.NewEntityUID(TypeFilePrefix, types.String(path[:k])))
	}
	for k := 1; k <= len(path); k++ {
		if path[k-1] != '/' {
			continue
		}
		out = append(out, types.NewEntityUID(TypeDir, types.String(path[:k])))
		if k > 1 {
			out = append(out, types.NewEntityUID(TypeDir, types.String(path[:k-1])))
		}
	}
	if dirSelf && !strings.HasSuffix(path, "/") {
		out = append(out,
			types.NewEntityUID(TypeDir, types.String(path+"/")),
			types.NewEntityUID(TypeDir, types.String(path)))
	}
	return out
}

// NormalizeHost canonicalizes a hostname the way requests and policies are
// compared: lowercased, surrounding space and one trailing dot removed.
func NormalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// CanonicalIPv4 returns the dotted IPv4 form of ip, or "" when ip is not an
// IPv4 (or IPv4-mapped) address. IPv6 is not supported in policies.
func CanonicalIPv4(ip string) string {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return ""
	}
	v4 := parsed.To4()
	if v4 == nil {
		return ""
	}
	return v4.String()
}

// connectResource builds the resource UID and parents of a connect request.
// hostname is the name the workload asked for (SNI/Host; may be empty), ip
// the destination IPv4 (may be empty), port the destination port (0 =
// unknown). An IP literal is never matched as a hostname.
func connectResource(hostname, ip string, port uint16) (types.EntityUID, []types.EntityUID, bool) {
	host := NormalizeHost(hostname)
	if lit := CanonicalIPv4(host); lit != "" || net.ParseIP(host) != nil {
		if ip == "" {
			ip = host
		}
		host = ""
	}
	ip = CanonicalIPv4(ip)
	if host == "" && ip == "" {
		return types.EntityUID{}, nil, false
	}

	var names []string
	if host != "" {
		names = append(names, host)
		for i := 0; i < len(host); i++ {
			if host[i] == '.' && i > 0 && i+1 < len(host) {
				names = append(names, "*"+host[i:])
			}
		}
	}
	if ip != "" {
		names = append(names, ip)
	}
	names = append(names, "*")

	parents := make([]types.EntityUID, 0, 2*len(names))
	for _, n := range names {
		parents = append(parents, types.NewEntityUID(TypeHost, types.String(n)))
		if port != 0 {
			parents = append(parents, types.NewEntityUID(TypeHost, types.String(n+":"+strconv.Itoa(int(port)))))
		}
	}
	id := host
	if id == "" {
		id = ip
	}
	return types.NewEntityUID(TypeHost, types.String(id)), parents, true
}

// NormalizeMCPServer canonicalizes an MCP server reference: lowercased, with
// any scheme, path and port removed.
func NormalizeMCPServer(server string) string {
	s := strings.ToLower(strings.TrimSpace(server))
	if s == "" {
		return ""
	}
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			if host := u.Hostname(); host != "" {
				s = host
			}
		}
	}
	if strings.Contains(s, "/") {
		s = strings.SplitN(s, "/", 2)[0]
	}
	if host, _, err := net.SplitHostPort(s); err == nil && host != "" {
		s = host
	}
	return strings.TrimSpace(s)
}

// NormalizeMCPTool canonicalizes an MCP tool name: lowercased and trimmed.
func NormalizeMCPTool(tool string) string { return strings.ToLower(strings.TrimSpace(tool)) }

func mcpResource(server, tool string) (types.EntityUID, []types.EntityUID) {
	uid := types.NewEntityUID(TypeMCPTool, types.String(NormalizeMCPTool(tool)))
	if s := NormalizeMCPServer(server); s != "" {
		return uid, []types.EntityUID{types.NewEntityUID(TypeMCPServer, types.String(s))}
	}
	return uid, nil
}

var fileOpenGroup = types.NewEntityUID(BuiltinActionType, ActionFileOpen)

// actionEntity returns the action entity of a built-in request, with its
// group: FileOpenReadOnly and FileOpenReadWrite are in Action::"FileOpen".
func actionEntity(id string) types.Entity {
	e := types.Entity{UID: types.NewEntityUID(BuiltinActionType, types.String(id))}
	if id == ActionFileOpenReadOnly || id == ActionFileOpenReadWrite {
		e.Parents = types.NewEntityUIDSet(fileOpenGroup)
	}
	return e
}
