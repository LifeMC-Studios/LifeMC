package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"lifemc-cli/pkg/scanner"
)

func TestParseScanFlags(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		apply   bool
		version string
		want    bool // whether an error is expected
	}{
		{name: "default", args: nil},
		{name: "apply", args: []string{"--apply"}, apply: true},
		{name: "dry-run", args: []string{"--dry-run"}},
		{name: "apply then dry-run", args: []string{"--apply", "--dry-run"}},
		{name: "version long", args: []string{"--version", "1.21.11"}, version: "1.21.11"},
		{name: "version short", args: []string{"-v", "1.18.2", "--apply"}, version: "1.18.2", apply: true},
		{name: "unknown", args: []string{"--force"}, want: true},
		{name: "version without value", args: []string{"--version"}, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flags, err := parseScanFlags(tc.args)
			if (err != nil) != tc.want {
				t.Fatalf("parseScanFlags(%v) error = %v, want err=%t", tc.args, err, tc.want)
			}
			if flags.apply != tc.apply {
				t.Errorf("parseScanFlags(%v).apply = %t, want %t", tc.args, flags.apply, tc.apply)
			}
			if flags.version != tc.version {
				t.Errorf("parseScanFlags(%v).version = %q, want %q", tc.args, flags.version, tc.version)
			}
		})
	}
}

func TestParseExportFlags(t *testing.T) {
	flags, err := parseExportFlags([]string{"--version", "1.20.6"})
	if err != nil {
		t.Fatalf("parseExportFlags() error = %v", err)
	}
	if flags.version != "1.20.6" {
		t.Errorf("version = %q, want 1.20.6", flags.version)
	}

	if _, err := parseExportFlags([]string{"--apply"}); err == nil {
		t.Fatal("parseExportFlags(--apply) error = nil, want usage error")
	}
}

func TestSessionScoped(t *testing.T) {
	s := session{root: "/src", versions: []scanner.Version{
		{Name: "1.18.2", Path: "/src/1.18.2"},
		{Name: "1.21.11", Path: "/src/1.21.11"},
	}}

	scoped, err := s.scoped("1.21.11")
	if err != nil {
		t.Fatalf("scoped() error = %v", err)
	}
	if len(scoped.versions) != 1 || scoped.versions[0].Name != "1.21.11" {
		t.Fatalf("scoped() = %+v, want only 1.21.11", scoped.versions)
	}

	all, err := s.scoped("")
	if err != nil || len(all.versions) != 2 {
		t.Fatalf("scoped(\"\") = %d versions, %v, want 2 and no error", len(all.versions), err)
	}

	if _, err := s.scoped("9.9.9"); err == nil {
		t.Fatal("scoped(9.9.9) error = nil, want error for unknown version")
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

	// --apply removes the file but still fails on the detection.
	if err := runScan(context.Background(), s, []string{"--apply"}); err == nil {
		t.Fatal("runScan(--apply) error = nil, want failure on findings")
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

func TestVerifySessionFailsOnProhibited(t *testing.T) {
	s, _ := versionWithFile(t, "evil.dll")

	if err := verifySession(s); err == nil {
		t.Fatal("verifySession() error = nil, want failure on prohibited file")
	}
}

func TestRunExportFailsClosed(t *testing.T) {
	s, _ := versionWithFile(t, "evil.sh")

	// Verification must abort the export before packwiz is ever invoked.
	if err := runExport(context.Background(), s, nil); err == nil {
		t.Fatal("runExport() error = nil, want fail-closed on prohibited file")
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
