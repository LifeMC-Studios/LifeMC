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

func TestScanConfigProhibited(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "config", "app.json"))
	mustWrite(t, filepath.Join(root, "config", "packed", "evil.sh"))

	report, err := Scan([]string{root}, Options{DryRun: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Reason, ".sh") {
		t.Fatalf("findings = %+v, want one .sh finding under config", report.Findings)
	}
	if got := report.Findings[0].File; got != filepath.Join("config", "packed", "evil.sh") {
		t.Errorf("file = %q, want config/packed/evil.sh", got)
	}
}

func TestScanConfigAllowsRegularFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "config", "fabric_loader_dependencies.json"))
	mustWrite(t, filepath.Join(root, "config", "yosbr", "settings.yaml"))

	report, err := Scan([]string{root}, Options{DryRun: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !report.Clean() {
		t.Fatalf("findings = %+v, want none for regular config files", report.Findings)
	}
}

func TestScanResourcepacksStrict(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "resourcepacks", "pack.pw.toml"))
	mustWrite(t, filepath.Join(root, "resourcepacks", "raw.zip"))

	report, err := Scan([]string{root}, Options{DryRun: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Reason, "unexpected") {
		t.Fatalf("findings = %+v, want one unexpected finding under resourcepacks", report.Findings)
	}
}

func TestScanCustomTargets(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mods", "evil.exe"))
	mustWrite(t, filepath.Join(root, "config", "evil.exe"))

	report, err := Scan([]string{root}, Options{DryRun: true, Targets: []Target{{Name: "config"}}})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 1 || !strings.HasPrefix(report.Findings[0].File, "config") {
		t.Fatalf("findings = %+v, want only the config target scanned", report.Findings)
	}
}

func TestScanFlagsSymlink(t *testing.T) {
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
	if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Reason, "symbolic link") {
		t.Fatalf("findings = %+v, want one symbolic link finding", report.Findings)
	}
}

func TestScanProhibitedExtensions(t *testing.T) {
	evil := []string{
		"payload.exe", "run.bat", "run.cmd", "run.ps1", "run.vbs", "setup.msi",
		"run.sh", "run.command", "lib.dll", "lib.so", "lib.dylib",
		"shortcut.lnk", "link.url", "mod.jar.bak", "legacy.old", "scratch.tmp",
	}

	for _, name := range evil {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			mustWrite(t, filepath.Join(root, "config", name))

			report, err := Scan([]string{root}, Options{DryRun: true})
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if len(report.Findings) != 1 {
				t.Fatalf("findings = %+v, want 1 for %q", report.Findings, name)
			}
		})
	}
}

func TestScanVersionedLibraries(t *testing.T) {
	evil := []string{"libfoo.so.1", "libfoo.so.1.2", "libbar.dylib.1.2"}

	for _, name := range evil {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			mustWrite(t, filepath.Join(root, "config", name))

			report, err := Scan([]string{root}, Options{DryRun: true})
			if err != nil {
				t.Fatalf("Scan() error = %v", err)
			}
			if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Reason, "versioned library") {
				t.Fatalf("findings = %+v, want one versioned library finding for %q", report.Findings, name)
			}
		})
	}
}

func TestScanRawBinaryWithoutExtension(t *testing.T) {
	root := t.TempDir()
	writeBytes(t, filepath.Join(root, "config", "payload"), []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01})

	report, err := Scan([]string{root}, Options{DryRun: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Reason, "raw binary") {
		t.Fatalf("findings = %+v, want one raw binary finding", report.Findings)
	}
}

func TestScanExtensionlessTextAllowed(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "config", "README"))

	report, err := Scan([]string{root}, Options{DryRun: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !report.Clean() {
		t.Fatalf("findings = %+v, want none for extensionless text", report.Findings)
	}
}

func TestScanHardlink(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "config")
	original := filepath.Join(dir, "data.json")
	mustWrite(t, original)
	if err := os.Link(original, filepath.Join(dir, "linked.json")); err != nil {
		t.Skipf("hardlink unsupported: %v", err)
	}

	report, err := Scan([]string{root}, Options{DryRun: true})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("findings = %+v, want 2 hard link findings", report.Findings)
	}
	for _, finding := range report.Findings {
		if !strings.Contains(finding.Reason, "hard link") {
			t.Errorf("reason = %q, want it to mention hard link", finding.Reason)
		}
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

func writeBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}
