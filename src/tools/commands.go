package main

import (
	"context"
	"fmt"

	"lifemc-cli/pkg/packwiz"
	"lifemc-cli/pkg/security"
	"lifemc-cli/pkg/validator"
)

// runVersions prints every discovered version.
func runVersions(_ context.Context, s session, _ []string) error {
	fmt.Printf("Active Minecraft versions in %s:\n", s.root)
	for _, version := range s.versions {
		fmt.Printf("  - %s (packwiz=%t, mods=%t)\n", version.Name, version.HasPackwiz, version.HasMods)
	}
	return nil
}

// runValidate checks every manifest against the approved CDN allowlist.
func runValidate(_ context.Context, s session, _ []string) error {
	roots := s.roots()
	if err := validator.Validate(roots, validator.DefaultAllowlist); err != nil {
		return err
	}
	fmt.Printf("Validated %d version(s): all download URLs use approved domains.\n", len(roots))
	return nil
}

// runScan scans every mods directory for prohibited files. It runs in dry-run
// mode unless --apply is passed, and fails when a dry-run finds any file.
func runScan(_ context.Context, s session, args []string) error {
	apply, err := parseApply(args)
	if err != nil {
		return err
	}

	report, err := security.Scan(s.roots(), security.Options{DryRun: !apply})
	if err != nil {
		return err
	}
	printReport(report, len(s.versions), apply)

	if !apply && !report.Clean() {
		return fmt.Errorf("scan: %d prohibited file(s) found (rerun with --apply to remove)", len(report.Findings))
	}
	return nil
}

// runVerify runs validate and scan as a single read-only gate.
func runVerify(_ context.Context, s session, args []string) error {
	if len(args) > 0 {
		return usagef("verify takes no arguments, got %q", args[0])
	}

	roots := s.roots()
	if err := validator.Validate(roots, validator.DefaultAllowlist); err != nil {
		return err
	}

	report, err := security.Scan(roots, security.Options{DryRun: true})
	if err != nil {
		return err
	}
	if !report.Clean() {
		printReport(report, len(s.versions), false)
		return fmt.Errorf("verify: %d prohibited file(s) found", len(report.Findings))
	}

	fmt.Printf("Verified %d version(s): manifests valid, no prohibited files.\n", len(roots))
	return nil
}

// runUpdate refreshes every external file via packwiz.
func runUpdate(ctx context.Context, s session, args []string) error {
	if len(args) > 0 {
		return usagef("update takes no arguments, got %q", args[0])
	}
	return eachPackwiz(ctx, s, "Updated", packwiz.Update)
}

// runExport builds a Modrinth .mrpack for every version via packwiz.
func runExport(ctx context.Context, s session, args []string) error {
	if len(args) > 0 {
		return usagef("export takes no arguments, got %q", args[0])
	}
	return eachPackwiz(ctx, s, "Exported", packwiz.Export)
}

// eachPackwiz runs op against every version that carries a packwiz manifest.
func eachPackwiz(ctx context.Context, s session, label string, op func(context.Context, string) error) error {
	done := 0
	for _, version := range s.versions {
		if !version.HasPackwiz {
			logger.Warn("skip version without pack.toml", "version", version.Name)
			continue
		}
		if err := op(ctx, version.Path); err != nil {
			return err
		}
		done++
	}
	fmt.Printf("%s %d of %d version(s).\n", label, done, len(s.versions))
	return nil
}

// parseApply reports whether --apply was requested; --dry-run is the default.
func parseApply(args []string) (bool, error) {
	apply := false
	for _, arg := range args {
		switch arg {
		case "--apply":
			apply = true
		case "--dry-run":
			apply = false
		default:
			return false, usagef("unknown flag %q (want: --apply, --dry-run)", arg)
		}
	}
	return apply, nil
}

// printReport renders a security report to stdout.
func printReport(report *security.Report, versions int, apply bool) {
	mode := "dry-run"
	if apply {
		mode = "apply"
	}
	if report.Clean() {
		fmt.Printf("Scanned %d version(s) in %s mode: no prohibited files found.\n", versions, mode)
		return
	}
	fmt.Printf("Scanned %d version(s) in %s mode: %d prohibited file(s) found.\n", versions, mode, len(report.Findings))
	for _, finding := range report.Findings {
		status := "flagged"
		if finding.Removed {
			status = "removed"
		}
		fmt.Printf("  - [%s] %s/%s: %s\n", status, finding.Version, finding.File, finding.Reason)
	}
}
