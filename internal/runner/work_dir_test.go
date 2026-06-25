package runner

import (
	"path/filepath"
	"testing"
)

// On macOS the per-run work dir must live under $HOME (shared into the Docker
// VM by default) rather than the system temp dir (/var/folders, not shared) so
// the /leash bind mount is visible inside the container. See issue #63.
func TestWorkDirBaseFor(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		goos string
		home string
		want string
	}{
		{
			name: "darwin anchors under home",
			goos: "darwin",
			home: "/Users/alice",
			want: filepath.Join("/Users/alice", ".leash", "run"),
		},
		{
			name: "darwin without home falls back to system temp",
			goos: "darwin",
			home: "",
			want: "",
		},
		{
			name: "linux keeps system temp",
			goos: "linux",
			home: "/home/alice",
			want: "",
		},
		{
			name: "windows keeps system temp",
			goos: "windows",
			home: `C:\Users\alice`,
			want: "",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := workDirBaseFor(tc.goos, tc.home); got != tc.want {
				t.Fatalf("workDirBaseFor(%q, %q) = %q, want %q", tc.goos, tc.home, got, tc.want)
			}
		})
	}
}
