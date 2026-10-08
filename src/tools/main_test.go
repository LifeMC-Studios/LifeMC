package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"lifemc-cli/pkg/scanner"
)

func TestParseApply(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		apply bool
		want  bool // whether an error is expected
	}{
		{name: "default", args: nil, apply: false},
		{name: "apply", args: []string{"--apply"}, apply: true},
		{name: "dry-run", args: []string{"--dry-run"}, apply: false},
		{name: "apply then dry-run", args: []string{"--apply", "--dry-run"}, apply: false},
		{name: "unknown", args: []string{"--force"}, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			apply, err := parseApply(tc.args)
			if (err != nil) != tc.want {
				t.Fatalf("parseApply(%v) error = %v, want err=%t", tc.args, err, tc.want)
			}
			if apply != tc.apply {
				t.Errorf("parseApply(%v) = %t, want %t", tc.args, apply, tc.apply)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	if _, ok := lookup("scan"); !ok {
		t.Error("lookup(scan) = false, want true")
	}
	if _, ok := lookup("nope"); ok {
		t.Error("lookup(nope) = true, want false")
	}
}

func TestRunScanDryRunFails(t *testing.T) {
	s, evil := versionWithFile(t, "evil.exe")

	if err := runScan(context.Background(), s, nil); err == nil {
		t.Fatal("runScan() error = nil, want failure on dry-run findings")
	}
	if _, err := os.Stat(evil); err != nil {
		t.Errorf("dry-run removed %q: %v", evil, err)
	}
}

func TestRunScanApplyRemoves(t *testing.T) {
	s, evil := versionWithFile(t, "evil.exe")

	if err := runScan(context.Background(), s, []string{"--apply"}); err != nil {
		t.Fatalf("runScan(--apply) error = %v, want nil", err)
	}
	if _, err := os.Stat(evil); !os.IsNotExist(err) {
		t.Errorf("file %q still present, want removed", evil)
	}
}

func TestRunVerifyFailsOnProhibited(t *testing.T) {
	s, _ := versionWithFile(t, "evil.exe")

	if err := runVerify(context.Background(), s, nil); err == nil {
		t.Fatal("runVerify() error = nil, want failure on prohibited file")
	}
}

// versionWithFile builds a session whose single version holds one mods file.
func versionWithFile(t *testing.T, name string) (session, string) {
	t.Helper()
	root := t.TempDir()
	mods := filepath.Join(root, "mods")
	if err := os.MkdirAll(mods, 0o755); err != nil {
		t.Fatalf("mkdir mods: %v", err)
	}
	path := filepath.Join(mods, name)
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}

	s := session{root: root, versions: []scanner.Version{{Name: "1.21.11", Path: root, HasMods: true}}}
	return s, path
}
