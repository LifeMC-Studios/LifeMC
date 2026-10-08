package validator

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateApprovedDomains(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mods", "sodium.pw.toml"), `
name = "Sodium"

[download]
url = "https://cdn.modrinth.com/data/AANobbMI/versions/c3YkZvne/sodium.jar"
hash-format = "sha512"
hash = "abc"
`)

	if err := Validate([]string{root}, nil); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateUnauthorizedDomain(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mods", "evil.pw.toml"), `
[download]
url = "https://evil.example.com/payload.jar"
`)

	err := Validate([]string{root}, nil)
	if err == nil {
		t.Fatal("Validate() error = nil, want ValidationError")
	}

	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("Validate() error type = %T, want *ValidationError", err)
	}
	if len(validationErr.Violations) != 1 {
		t.Fatalf("violations = %d, want 1", len(validationErr.Violations))
	}
	if !strings.Contains(validationErr.Violations[0].Reason, "evil.example.com") {
		t.Errorf("reason = %q, want it to mention evil.example.com", validationErr.Violations[0].Reason)
	}
}

func TestValidateInvalidTOML(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "mods", "broken.pw.toml"), "url = \n")

	var validationErr *ValidationError
	if err := Validate([]string{root}, nil); !errors.As(err, &validationErr) {
		t.Fatalf("Validate() error = %v, want *ValidationError", err)
	}
	if len(validationErr.Violations) != 1 || !strings.Contains(validationErr.Violations[0].Reason, "invalid TOML") {
		t.Fatalf("violations = %+v, want one invalid TOML violation", validationErr.Violations)
	}
}

func TestValidateNestedFiles(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "index.toml"), `
hash-format = "sha256"

[[files]]
file = "mods/remote.jar"

[files.download]
url = "https://raw.githubusercontent.com/LifeMC/pack/main/remote.jar"
`)

	if err := Validate([]string{root}, nil); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestValidateNoRoots(t *testing.T) {
	if err := Validate(nil, nil); err == nil {
		t.Fatal("Validate() error = nil, want error for empty roots")
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %q: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %q: %v", path, err)
	}
}
