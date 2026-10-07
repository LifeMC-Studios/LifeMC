// Command lifemc-cli is the LifeMC modpack maintenance CLI.
package main

import (
	"fmt"
	"log/slog"
	"os"

	"lifemc-cli/pkg/scanner"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if err := run(); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

// run discovers the active Minecraft versions and reports them.
func run() error {
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("resolve working directory: %w", err)
	}

	root, err := scanner.ResolveRoot(wd)
	if err != nil {
		return err
	}

	versions, err := scanner.Discover(root)
	if err != nil {
		return err
	}

	fmt.Printf("Active Minecraft versions in %s:\n", root)
	for _, version := range versions {
		fmt.Printf("  - %s (packwiz=%t, mods=%t)\n", version.Name, version.HasPackwiz, version.HasMods)
	}
	return nil
}
