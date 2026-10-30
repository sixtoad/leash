package configstore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeLeashResources(t *testing.T) {
	cfg := New()
	data := []byte("[leash.resources]\ncpus = 1.5\nmemory = \"2g\"\npids_limit = 256\nshm_size = \"1g\"\n")
	if err := decodeConfig(data, "test.toml", &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := ResourceLimits{CPUs: "1.5", Memory: "2g", PidsLimit: "256", ShmSize: "1g"}
	if cfg.Resources != want {
		t.Fatalf("Resources = %+v, want %+v", cfg.Resources, want)
	}
}

func TestDecodeLeashResourcesRejectsUnknownAndBadTypes(t *testing.T) {
	for name, data := range map[string]string{
		"unknown key": "[leash.resources]\nswap = \"1g\"\n",
		"bad type":    "[leash.resources]\ncpus = true\n",
		"not a table": "[leash]\nresources = \"2g\"\n",
	} {
		cfg := New()
		if err := decodeConfig([]byte(data), "test.toml", &cfg); err == nil || !strings.Contains(err.Error(), "leash.resources") {
			t.Fatalf("%s: want leash.resources error, got %v", name, err)
		}
	}
}

// .leash.toml overrides individual limits from the global config.
func TestLoadWithOverlayMergesResources(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))
	cfgDir := filepath.Join(base, "leash")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	global := "[leash.resources]\ncpus = \"2\"\nmemory = \"4g\"\nshm_size = \"512m\"\n"
	if err := os.WriteFile(filepath.Join(cfgDir, configFileName), []byte(global), 0o600); err != nil {
		t.Fatal(err)
	}
	project := t.TempDir()
	local := "[leash.resources]\nmemory = \"1g\"\npids_limit = 128\n"
	if err := os.WriteFile(filepath.Join(project, LocalConfigFileName), []byte(local), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadWithOverlay(project)
	if err != nil {
		t.Fatalf("LoadWithOverlay: %v", err)
	}
	want := ResourceLimits{CPUs: "2", Memory: "1g", PidsLimit: "128", ShmSize: "512m"}
	if cfg.Resources != want {
		t.Fatalf("Resources = %+v, want %+v", cfg.Resources, want)
	}
}

// Saving a loaded config keeps [leash.resources].
func TestSaveRoundTripsResources(t *testing.T) {
	testSetEnv(t, "LEASH_HOME", "")
	base := t.TempDir()
	testSetEnv(t, "XDG_CONFIG_HOME", base)
	setHome(t, filepath.Join(base, "home"))
	cfg := New()
	cfg.Resources = ResourceLimits{CPUs: "0.5", Memory: "512m", PidsLimit: "64", ShmSize: "1g"}
	if err := Save(cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.Resources != cfg.Resources {
		t.Fatalf("round-trip Resources = %+v, want %+v", loaded.Resources, cfg.Resources)
	}
	if clone := loaded.Clone(); clone.Resources != cfg.Resources {
		t.Fatalf("Clone dropped Resources: %+v", clone.Resources)
	}
}
