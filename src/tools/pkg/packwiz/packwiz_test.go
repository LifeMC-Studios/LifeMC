package packwiz

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRunEmptyDir(t *testing.T) {
	if err := Update(context.Background(), ""); err == nil {
		t.Fatal("Update() error = nil, want error for empty dir")
	}
}

func TestRunBinaryMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	if err := Update(context.Background(), t.TempDir()); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("Update() error = %v, want ErrNotInstalled", err)
	}
}

func TestRunExecutesFakeBinary(t *testing.T) {
	withFakeBinary(t, "#!/bin/sh\nexit 0\n")

	if err := Update(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("Update() error = %v, want nil", err)
	}
}

func TestRunPropagatesFailure(t *testing.T) {
	withFakeBinary(t, "#!/bin/sh\nexit 3\n")

	if err := Export(context.Background(), t.TempDir()); err == nil {
		t.Fatal("Export() error = nil, want failure from fake binary")
	}
}

// withFakeBinary installs a fake packwiz script on PATH for the test.
func withFakeBinary(t *testing.T, body string) {
	t.Helper()
	bin := t.TempDir()
	script := filepath.Join(bin, Binary)
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}
