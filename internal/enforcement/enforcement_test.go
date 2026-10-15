package enforcement

import (
	"errors"
	"testing"
)

func TestResolveRequireLSM(t *testing.T) {
	cases := []struct {
		name          string
		require       bool
		allow         bool
		env           map[string]string
		want, wantErr bool
	}{
		{name: "nothing set fails closed", want: true},
		{name: "--require-lsm accepted", require: true, want: true},
		{name: "--allow-proxy-only opts out", allow: true, want: false},
		{name: "both flags conflict", require: true, allow: true, wantErr: true},
		{name: "LEASH_REQUIRE_LSM=1 redundant", env: map[string]string{EnvRequireLSM: "1"}, want: true},
		{name: "falsy LEASH_REQUIRE_LSM does not opt out", env: map[string]string{EnvRequireLSM: "false"}, want: true},
		{name: "LEASH_ALLOW_PROXY_ONLY=yes opts out", env: map[string]string{EnvAllowProxyOnly: "yes"}, want: false},
		{name: "LEASH_ALLOW_PROXY_ONLY=0 is not an opt-out", env: map[string]string{EnvAllowProxyOnly: "0"}, want: true},
		{name: "both env conflict", env: map[string]string{EnvRequireLSM: "1", EnvAllowProxyOnly: "1"}, wantErr: true},
		{name: "allow flag beats require env", allow: true, env: map[string]string{EnvRequireLSM: "1"}, want: false},
		{name: "require flag beats allow env", require: true, env: map[string]string{EnvAllowProxyOnly: "1"}, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(k string) string { return tc.env[k] }
			got, err := ResolveRequireLSM(tc.require, tc.allow, getenv)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error")
				}
				if !got {
					t.Fatal("a conflict must still resolve to fail-closed")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("requireLSM = %v, want %v", got, tc.want)
			}
		})
	}
	if got, err := ResolveRequireLSM(false, false, nil); err != nil || !got {
		t.Fatalf("nil getenv: got (%v, %v), want (true, nil)", got, err)
	}
	if _, err := ResolveRequireLSM(true, true, nil); !errors.Is(err, ErrConflictingLSMMode) {
		t.Fatalf("flag conflict should be ErrConflictingLSMMode, got %v", err)
	}
}

func TestStatusCheck(t *testing.T) {
	if err := Describe(true, false, true).Check(true); err != nil {
		t.Fatalf("lsm under fail-closed must pass: %v", err)
	}
	if err := Describe(false, true, false).Check(false); err != nil {
		t.Fatalf("proxy-only when allowed must pass: %v", err)
	}
	if err := Describe(false, true, true).Check(true); err == nil {
		t.Fatal("proxy-only under fail-closed must be refused")
	}
	if err := Describe(false, false, false).Check(false); err == nil {
		t.Fatal("none must be refused even with proxy-only allowed")
	}
}

func TestDescribe(t *testing.T) {
	cases := []struct {
		l1, l2, require bool
		want            Status
	}{
		{true, true, true, Status{LevelLSM, LayerActive, LayerActive, true, false}},
		{true, false, true, Status{LevelLSM, LayerActive, LayerDisabled, true, false}},
		{false, true, false, Status{LevelProxyOnly, LayerUnavailable, LayerActive, false, true}},
		{false, false, false, Status{LevelNone, LayerUnavailable, LayerDisabled, false, true}},
	}
	for _, tc := range cases {
		if got := Describe(tc.l1, tc.l2, tc.require); got != tc.want {
			t.Errorf("Describe(%v,%v,%v) = %+v, want %+v", tc.l1, tc.l2, tc.require, got, tc.want)
		}
	}
}
