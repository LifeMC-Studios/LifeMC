// Package packwiz wraps the external packwiz binary to run maintenance
// operations across a modpack directory.
package packwiz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// Binary is the executable invoked for every operation.
const Binary = "packwiz"

// logger tags every record emitted by this package.
var logger = slog.With("module", "packwiz")

// ErrNotInstalled is returned when the packwiz binary is missing from PATH.
var ErrNotInstalled = errors.New("packwiz: binary not found in PATH")

// Update refreshes every external file in the modpack rooted at dir.
func Update(ctx context.Context, dir string) error {
	return run(ctx, dir, "update", "--all", "-y")
}

// Export builds a Modrinth .mrpack artifact for the modpack rooted at dir.
func Export(ctx context.Context, dir string) error {
	return run(ctx, dir, "modrinth", "export")
}

// run executes packwiz with args inside dir, streaming its output.
func run(ctx context.Context, dir string, args ...string) error {
	if dir == "" {
		return errors.New("packwiz: directory is empty")
	}
	if _, err := exec.LookPath(Binary); err != nil {
		return fmt.Errorf("%w: %v", ErrNotInstalled, err)
	}

	logger.Debug("run start", "dir", dir, "args", args)
	cmd := exec.CommandContext(ctx, Binary, args...)
	cmd.Dir = dir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("packwiz: %s in %q: %w", strings.Join(args, " "), dir, err)
	}
	logger.Debug("run done", "dir", dir, "args", args)
	return nil
}
