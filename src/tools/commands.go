package main

import (
	"context"
	"fmt"

	"lifemc-cli/pkg/packwiz"
	"lifemc-cli/pkg/security"
	"lifemc-cli/pkg/ui"
	"lifemc-cli/pkg/validator"
)

// runVersions prints every discovered version.
func runVersions(_ context.Context, s session, _ []string) error {
	lines := make([]string, 0, len(s.versions))
	for _, version := range s.versions {
		state := ui.Subtle(fmt.Sprintf("packwiz:%t  mods:%t", version.HasPackwiz, version.HasMods))
		lines = append(lines, ui.Strong(version.Name)+"  "+state)
	}

	fmt.Println(ui.Header("Active Minecraft versions"))
	fmt.Println(ui.Box(s.root, lines))
	return nil
}

// runValidate checks every manifest against the approved CDN allowlist.
func runValidate(_ context.Context, s session, _ []string) error {
	fmt.Println(ui.Header("CDN validation"))

	roots := s.roots()
	if err := validator.Validate(roots, validator.DefaultAllowlist); err != nil {
		fmt.Println(ui.Report("Result", ui.StatusError, err.Error(), nil))
		return err
	}

	summary := fmt.Sprintf("%d version(s): all download URLs use approved domains", len(roots))
	fmt.Println(ui.Report("Result", ui.StatusSuccess, summary, nil))
	return nil
}

// runScan scans a version's payload directories for prohibited files. It runs
// in dry-run mode unless --apply is passed and always fails when it finds any
// file. --version/-v scopes the scan to a single version.
func runScan(_ context.Context, s session, args []string) error {
	flags, err := parseScanFlags(args)
	if err != nil {
		return err
	}

	scoped, err := s.scoped(flags.version)
	if err != nil {
		return err
	}

	report, err := security.Scan(scoped.roots(), security.Options{DryRun: !flags.apply})
	if err != nil {
		return err
	}

	fmt.Println(ui.Header("Security scan"))
	fmt.Println(ui.Report("Result", scanStatus(report, flags.apply), scanSummary(report), scanDetails(report)))

	if !report.Clean() {
		return fmt.Errorf("scan: %d prohibited file(s) detected", len(report.Findings))
	}
	return nil
}

// runVerify runs validate and scan as a single read-only gate.
func runVerify(_ context.Context, s session, args []string) error {
	if len(args) > 0 {
		return usagef("verify takes no arguments, got %q", args[0])
	}

	fmt.Println(ui.Header("Verification"))

	report, err := verifySession(s)
	if err != nil {
		fmt.Println(ui.Report("Result", ui.StatusError, err.Error(), scanDetails(report)))
		return err
	}

	summary := fmt.Sprintf("%d version(s): manifests valid, no prohibited files", len(s.versions))
	fmt.Println(ui.Report("Result", ui.StatusSuccess, summary, nil))
	return nil
}

// verifySession runs the CDN allowlist check and the security scan across the
// session, returning the security report and the first anomaly (fail-closed).
func verifySession(s session) (*security.Report, error) {
	roots := s.roots()
	if err := validator.Validate(roots, validator.DefaultAllowlist); err != nil {
		return nil, err
	}

	report, err := security.Scan(roots, security.Options{DryRun: true})
	if err != nil {
		return nil, err
	}
	if !report.Clean() {
		return report, fmt.Errorf("security: %d prohibited file(s) detected", len(report.Findings))
	}
	return report, nil
}

// runUpdate refreshes every external file via packwiz.
func runUpdate(ctx context.Context, s session, args []string) error {
	if len(args) > 0 {
		return usagef("update takes no arguments, got %q", args[0])
	}

	fmt.Println(ui.Header("Update"))

	done, err := eachPackwiz(ctx, s, packwiz.Update)
	if err != nil {
		return err
	}

	summary := fmt.Sprintf("updated %d of %d version(s)", done, len(s.versions))
	fmt.Println(ui.Report("Result", ui.StatusSuccess, summary, nil))
	return nil
}

// runExport builds a Modrinth .mrpack for every version via packwiz.
// --version/-v scopes the export to a single version. It is fail-closed: the
// export is aborted when verification finds any anomaly.
func runExport(ctx context.Context, s session, args []string) error {
	flags, err := parseExportFlags(args)
	if err != nil {
		return err
	}

	scoped, err := s.scoped(flags.version)
	if err != nil {
		return err
	}

	fmt.Println(ui.Header("Export"))

	report, err := verifySession(scoped)
	if err != nil {
		fmt.Println(ui.Report("Aborted", ui.StatusError, "export blocked: "+err.Error(), scanDetails(report)))
		return fmt.Errorf("export aborted: %w", err)
	}

	done, err := eachPackwiz(ctx, scoped, packwiz.Export)
	if err != nil {
		return err
	}

	summary := fmt.Sprintf("exported %d of %d version(s)", done, len(scoped.versions))
	fmt.Println(ui.Report("Result", ui.StatusSuccess, summary, nil))
	return nil
}

// eachPackwiz runs op against every version that carries a packwiz manifest,
// returning the number of versions processed.
func eachPackwiz(ctx context.Context, s session, op func(context.Context, string) error) (int, error) {
	done := 0
	for _, version := range s.versions {
		if !version.HasPackwiz {
			logger.Warn("skip version without pack.toml", "version", version.Name)
			continue
		}
		if err := op(ctx, version.Path); err != nil {
			return done, err
		}
		done++
	}
	return done, nil
}

// scanStatus selects the badge for a security report.
func scanStatus(report *security.Report, apply bool) string {
	switch {
	case !report.Clean():
		return ui.StatusError
	case apply:
		return ui.StatusSuccess
	default:
		return ui.StatusDryRun
	}
}

// scanSummary renders the one-line summary of a security report.
func scanSummary(report *security.Report) string {
	if report.Clean() {
		return "no prohibited files found"
	}
	return fmt.Sprintf("%d prohibited file(s) detected", len(report.Findings))
}

// scanDetails renders one row per prohibited file. A nil report yields no rows.
func scanDetails(report *security.Report) []string {
	if report == nil {
		return nil
	}

	details := make([]string, 0, len(report.Findings))
	for _, finding := range report.Findings {
		status := "flagged"
		if finding.Removed {
			status = "removed"
		}
		details = append(details, fmt.Sprintf("  %s %s/%s — %s", ui.Subtle("["+status+"]"), finding.Version, finding.File, finding.Reason))
	}
	return details
}

// scanFlags configures the scan command.
type scanFlags struct {
	apply   bool
	version string
}

// parseScanFlags parses the scan command flags. The last value wins.
func parseScanFlags(args []string) (scanFlags, error) {
	flags := scanFlags{}
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; arg {
		case "--apply":
			flags.apply = true
		case "--dry-run":
			flags.apply = false
		case "--version", "-v":
			value, next, err := takeValue(args, i, arg)
			if err != nil {
				return scanFlags{}, err
			}
			flags.version, i = value, next
		default:
			return scanFlags{}, usagef("unknown flag %q (want: --apply, --dry-run, --version)", arg)
		}
	}
	return flags, nil
}

// exportFlags configures the export command.
type exportFlags struct {
	version string
}

// parseExportFlags parses the export command flags. The last value wins.
func parseExportFlags(args []string) (exportFlags, error) {
	flags := exportFlags{}
	for i := 0; i < len(args); i++ {
		switch arg := args[i]; arg {
		case "--version", "-v":
			value, next, err := takeValue(args, i, arg)
			if err != nil {
				return exportFlags{}, err
			}
			flags.version, i = value, next
		default:
			return exportFlags{}, usagef("unknown flag %q (want: --version)", arg)
		}
	}
	return flags, nil
}

// takeValue reads the value following a value flag located at index i.
func takeValue(args []string, i int, flag string) (string, int, error) {
	next := i + 1
	if next >= len(args) {
		return "", i, usagef("flag %q requires a value", flag)
	}
	return args[next], next, nil
}
