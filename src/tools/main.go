// Command lifemc-cli is the LifeMC modpack maintenance CLI.
package main

import (
	"fmt"
	"log/slog"
	"os"

	"lifemc-cli/pkg/scanner"
	"lifemc-cli/pkg/validator"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if err := run(os.Args[1:]); err != nil {
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

// run dispatches the CLI subcommand against the discovered versions.
func run(args []string) error {
	command := "versions"
	if len(args) > 0 {
		command = args[0]
	}
	if command != "versions" && command != "validate" && command != "scan" {
		return fmt.Errorf("unknown command %q (want: versions, validate, scan)", command)
	}

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

	switch command {
	case "validate":
		return validateVersions(versions)
	case "scan":
		return scanVersions(versions, args[1:])
	default:
		return listVersions(root, versions)
	}
}

// listVersions prints every discovered version.
func listVersions(root string, versions []scanner.Version) error {
	fmt.Printf("Active Minecraft versions in %s:\n", root)
	for _, version := range versions {
		fmt.Printf("  - %s (packwiz=%t, mods=%t)\n", version.Name, version.HasPackwiz, version.HasMods)
	}
	return nil
}

// validateVersions checks every manifest against the approved CDN allowlist.
func validateVersions(versions []scanner.Version) error {
	roots := make([]string, len(versions))
	for i, version := range versions {
		roots[i] = version.Path
	}

	if err := validator.Validate(roots, validator.DefaultAllowlist); err != nil {
		return err
	}

	fmt.Printf("Validated %d version(s): all download URLs use approved domains.\n", len(roots))
	return nil
}
