package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFlagsProhibitedInDryRun(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mods", "sodium.pw.toml"))
	evil := filepath.Join(root, "mods", "payload.exe")
	mustWrite(t, evil)

	report, err := Scan([]string{root}, Options{DryRun: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(report.Findings))
	}
	if report.Findings[0].Removed {
		t.Error("finding.Removed = true, want false in dry-run")
	}
	if !strings.Contains(report.Findings[0].Reason, ".exe") {
		t.Errorf("reason = %q, want it to mention .exe", report.Findings[0].Reason)
	}
	if _, err := os.Stat(evil); err != nil {
		t.Errorf("dry-run removed %q: %v", evil, err)
	}
}

func TestScanRemovesProhibited(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mods", "sodium.pw.toml"))
	evil := filepath.Join(root, "mods", "payload.bat")
	mustWrite(t, evil)

	report, err := Scan([]string{root}, Options{DryRun: false})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 1 || !report.Findings[0].Removed {
		t.Fatalf("findings = %+v, want one removed finding", report.Findings)
	}
	if _, err := os.Stat(evil); !os.IsNotExist(err) {
		t.Errorf("file %q still present, want removed", evil)
	}
}

func TestScanFlagsUnexpectedFile(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mods", "sodium.pw.toml"))
	mustWrite(t, filepath.Join(root, "mods", "stray.jar"))

	report, err := Scan([]string{root}, Options{DryRun: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(report.Findings))
	}
	if !strings.Contains(report.Findings[0].Reason, "unexpected") {
		t.Errorf("reason = %q, want it to mention unexpected", report.Findings[0].Reason)
	}
}

func TestScanFlagsNonRegularFile(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mods", "sodium.pw.toml"))
	link := filepath.Join(root, "mods", "linked.pw.toml")
	if err := os.Symlink(filepath.Join(root, "mods", "sodium.pw.toml"), link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}

	report, err := Scan([]string{root}, Options{DryRun: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Reason, "non-regular") {
		t.Fatalf("findings = %+v, want one non-regular finding", report.Findings)
	}
}

func TestScanCustomProhibited(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mods", "sodium.pw.toml"))
	mustWrite(t, filepath.Join(root, "mods", "notes.txt"))

	report, err := Scan([]string{root}, Options{DryRun: true, Prohibited: []string{".txt"}})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Reason, ".txt") {
		t.Fatalf("findings = %+v, want one .txt finding", report.Findings)
	}
}

func TestScanNoModsDirectory(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "pack.toml"))

	report, err := Scan([]string{root}, Options{DryRun: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !report.Clean() {
		t.Fatalf("findings = %+v, want none", report.Findings)
	}
}

func TestScanNoRoots(t *testing.T) {
	if _, err := Scan(nil, Options{}); err == nil {
		t.Fatal("Scan() error = nil, want error for empty roots")
	}
}

func TestScanMissingRoot(t *testing.T) {
	if _, err := Scan([]string{filepath.Join(t.TempDir(), "absent")}, Options{}); err == nil {
		t.Fatal("Scan() error = nil, want error for missing root")
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
