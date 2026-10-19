package hardening

import (
	"fmt"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

// Identity is the user a hardened launch switches to.
type Identity struct {
	Name   string
	UID    int
	GID    int
	Groups []int // supplementary groups, as initgroups(3) would set them
	Home   string
	Shell  string
}

// LookupIdentity resolves name through NSS (getent passwd, id -G), so LDAP or
// SSSD users resolve as they did for runuser; it falls back to os/user (which,
// in a static build, reads /etc/passwd and /etc/group) when getent is absent.
func LookupIdentity(name string) (*Identity, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("empty user name")
	}
	var id *Identity
	if out, err := exec.Command("getent", "passwd", name).Output(); err == nil {
		id, err = parsePasswd(strings.TrimSpace(string(out)))
		if err != nil {
			return nil, fmt.Errorf("user %s: %w", name, err)
		}
	} else if _, missing := err.(*exec.Error); !missing {
		return nil, fmt.Errorf("unknown user %s (getent passwd: %v)", name, err)
	} else {
		u, err := user.Lookup(name)
		if err != nil {
			return nil, fmt.Errorf("unknown user %s: %w", name, err)
		}
		id = &Identity{Name: u.Username, Home: u.HomeDir}
		if id.UID, err = strconv.Atoi(u.Uid); err != nil {
			return nil, fmt.Errorf("user %s: uid %q: %w", name, u.Uid, err)
		}
		if id.GID, err = strconv.Atoi(u.Gid); err != nil {
			return nil, fmt.Errorf("user %s: gid %q: %w", name, u.Gid, err)
		}
	}
	groups, err := lookupGroups(id)
	if err != nil {
		return nil, err
	}
	id.Groups = groups
	return id, nil
}

func lookupGroups(id *Identity) ([]int, error) {
	var fields []string
	if out, err := exec.Command("id", "-G", id.Name).Output(); err == nil {
		fields = strings.Fields(string(out))
	} else if u, uerr := user.Lookup(id.Name); uerr == nil {
		ids, gerr := u.GroupIds()
		if gerr != nil {
			return nil, fmt.Errorf("groups of %s: %w", id.Name, gerr)
		}
		fields = ids
	} else {
		return nil, fmt.Errorf("groups of %s: %v", id.Name, err)
	}
	groups := []int{}
	seen := map[int]bool{}
	for _, f := range append([]string{strconv.Itoa(id.GID)}, fields...) {
		g, err := strconv.Atoi(f)
		if err != nil {
			return nil, fmt.Errorf("groups of %s: %q is not a gid", id.Name, f)
		}
		if !seen[g] {
			seen[g] = true
			groups = append(groups, g)
		}
	}
	return groups, nil
}

// parsePasswd parses one passwd(5) line: name:password:uid:gid:gecos:home:shell.
func parsePasswd(line string) (*Identity, error) {
	f := strings.Split(line, ":")
	if len(f) != 7 {
		return nil, fmt.Errorf("malformed passwd entry %q", line)
	}
	uid, err := strconv.Atoi(f[2])
	if err != nil {
		return nil, fmt.Errorf("passwd uid %q: %w", f[2], err)
	}
	gid, err := strconv.Atoi(f[3])
	if err != nil {
		return nil, fmt.Errorf("passwd gid %q: %w", f[3], err)
	}
	return &Identity{Name: f[0], UID: uid, GID: gid, Home: f[5], Shell: f[6]}, nil
}

// UserEnv returns env with the variables runuser -u (su without a login
// shell) sets for a non-root target: HOME, SHELL, USER and LOGNAME. Everything
// else is kept.
func UserEnv(env []string, id *Identity) []string {
	shell := id.Shell
	if shell == "" {
		shell = "/bin/sh"
	}
	set := map[string]string{"HOME": id.Home, "SHELL": shell, "USER": id.Name, "LOGNAME": id.Name}
	out := make([]string, 0, len(env)+len(set))
	for _, kv := range env {
		k, _, _ := strings.Cut(kv, "=")
		if _, ok := set[k]; ok {
			continue
		}
		out = append(out, kv)
	}
	for _, k := range []string{"HOME", "SHELL", "USER", "LOGNAME"} {
		out = append(out, k+"="+set[k])
	}
	return out
}
