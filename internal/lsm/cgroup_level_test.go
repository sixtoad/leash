package lsm

import "testing"

// cgroupLevel must equal the kernel cgroup depth that
// bpf_get_current_ancestor_cgroup_id indexes by: the unified root is 0 and each
// nesting adds one. A wrong level would make the hierarchy check compare against
// the wrong ancestor and silently mis-scope enforcement.
func TestCgroupLevel(t *testing.T) {
	cases := map[string]int{
		"/sys/fs/cgroup":                                     0,
		"/sys/fs/cgroup/":                                    0,
		"/sys/fs/cgroup/system.slice":                        1,
		"/sys/fs/cgroup/system.slice/leash-native-x.service": 2,
		"/sys/fs/cgroup/system.slice/leash-native-x.service/": 2,
		"/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.service": 4,
	}
	for path, want := range cases {
		if got := cgroupLevel(path); got != want {
			t.Errorf("cgroupLevel(%q) = %d, want %d", path, got, want)
		}
	}
}
