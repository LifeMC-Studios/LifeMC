package scanner

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscover(t *testing.T) {
	root := t.TempDir()

	// Active versions.
	mustMkdir(t, filepath.Join(root, "1.18.2", "mods"))
	mustWrite(t, filepath.Join(root, "1.21.11", "pack.toml"))
	// Ignored: the tools directory and a non-version directory.
	mustMkdir(t, filepath.Join(root, "tools", "pkg"))
	mustMkdir(t, filepath.Join(root, "assets"))
	// Version-shaped directory without packwiz or mods configuration.
	mustMkdir(t, filepath.Join(root, "1.20.6"))

	versions, err := Discover(root)
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}

	if len(versions) != 2 {
		t.Fatalf("Discover() returned %d versions, want 2", len(versions))
	}
	if got := names(versions); got[0] != "1.18.2" || got[1] != "1.21.11" {
		t.Fatalf("Discover() order = %v, want [1.18.2 1.21.11]", got)
	}
	if !versions[0].HasMods || versions[0].HasPackwiz {
		t.Errorf("1.18.2 flags = packwiz:%t mods:%t, want packwiz:false mods:true", versions[0].HasPackwiz, versions[0].HasMods)
	}
	if !versions[1].HasPackwiz || versions[1].HasMods {
		t.Errorf("1.21.11 flags = packwiz:%t mods:%t, want packwiz:true mods:false", versions[1].HasPackwiz, versions[1].HasMods)
	}
}

func TestDiscoverEmptyRoot(t *testing.T) {
	if _, err := Discover(t.TempDir()); !errors.Is(err, ErrNoVersions) {
		t.Fatalf("Discover() error = %v, want ErrNoVersions", err)
	}
}

func TestResolveRoot(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	tools := filepath.Join(src, "tools")
	mustMkdir(t, filepath.Join(src, "1.21.11", "mods"))
	mustMkdir(t, tools)

	got, err := ResolveRoot(tools)
	if err != nil {
		t.Fatalf("ResolveRoot() error = %v", err)
	}
	if got != src {
		t.Fatalf("ResolveRoot() = %q, want %q", got, src)
	}
}

func names(versions []Version) []string {
	out := make([]string, len(versions))
	for i, version := range versions {
		out[i] = version.Name
	}
	return out
}

func mustMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", path, err)
	}
}

func mustWrite(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte("name = \"test\"\n"), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}
