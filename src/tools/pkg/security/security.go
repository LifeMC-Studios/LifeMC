// Package security scans the mods directory of every active Minecraft version
// for prohibited files and, when requested, removes them.
package security

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// modSuffix is the only file type expected inside a packwiz mods directory.
const modSuffix = ".pw.toml"

// DefaultProhibited lists the file suffixes that must never ship inside a mods
// directory.
var DefaultProhibited = []string{
	".exe",
	".bat",
	".sh",
	".jar.bak",
}

// logger tags every record emitted by this package.
var logger = slog.With("module", "security")

// Options configures a scan run.
type Options struct {
	// DryRun reports findings without deleting anything. It is the safe default.
	DryRun bool
	// Prohibited holds the lowercase file suffixes to flag. A nil or empty slice
	// falls back to DefaultProhibited.
	Prohibited []string
}

// Finding describes a single prohibited file discovered during a scan.
type Finding struct {
	Version string // version directory name, e.g. "1.21.11"
	File    string // path relative to the version directory
	Reason  string // why the file was flagged
	Removed bool   // whether the file was deleted from disk
}

// Report aggregates every finding produced by a scan run.
type Report struct {
	Findings []Finding
}

// Clean reports whether the scan found no prohibited file.
func (r *Report) Clean() bool {
	return len(r.Findings) == 0
}

// Scan walks the mods directory of every root and flags prohibited files. When
// opts.DryRun is false the flagged files are deleted. It returns a Report
// describing every action taken; a nil report is never returned alongside a nil
// error.
func Scan(roots []string, opts Options) (*Report, error) {
	if len(roots) == 0 {
		return nil, errors.New("security: no roots provided")
	}

	prohibited := normalize(opts.Prohibited)
	logger.Debug("scan start", "roots", len(roots), "dry_run", opts.DryRun, "prohibited", len(prohibited))

	report := &Report{Findings: make([]Finding, 0)}
	for _, root := range roots {
		findings, err := scanRoot(root, prohibited, opts.DryRun)
		if err != nil {
			return nil, err
		}
		report.Findings = append(report.Findings, findings...)
	}

	logger.Debug("scan done", "roots", len(roots), "findings", len(report.Findings))
	return report, nil
}

// scanRoot walks the mods directory of a single version root.
func scanRoot(root string, prohibited []string, dryRun bool) ([]Finding, error) {
	mods, err := modsDir(root)
	if err != nil {
		return nil, err
	}
	if mods == "" {
		logger.Debug("mods directory absent", "root", root)
		return nil, nil
	}

	version := filepath.Base(root)
	findings := make([]Finding, 0)
	err = filepath.WalkDir(mods, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		reason := classify(entry.Name(), prohibited)
		if reason == "" && !entry.Type().IsRegular() {
			reason = "unexpected non-regular file"
		}
		if reason == "" {
			return nil
		}

		finding := Finding{
			Version: version,
			File:    relative(root, path),
			Reason:  reason,
		}
		if !dryRun {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("remove %q: %w", path, err)
			}
			finding.Removed = true
		}

		logger.Warn("prohibited file", "version", version, "file", finding.File, "reason", reason, "removed", finding.Removed)
		findings = append(findings, finding)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("security: walk %q: %w", mods, err)
	}
	return findings, nil
}

// modsDir resolves the mods directory of root, returning "" when it is absent.
func modsDir(root string) (string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return "", fmt.Errorf("security: stat root %q: %w", root, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("security: root %q is not a directory", root)
	}

	mods := filepath.Join(root, "mods")
	info, err = os.Stat(mods)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("security: stat mods %q: %w", mods, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("security: mods path %q is not a directory", mods)
	}
	return mods, nil
}

// classify returns the reason name is prohibited, or "" when it is a valid
// packwiz mod manifest.
func classify(name string, prohibited []string) string {
	lower := strings.ToLower(name)
	for _, suffix := range prohibited {
		if strings.HasSuffix(lower, suffix) {
			return fmt.Sprintf("prohibited file type %q", suffix)
		}
	}
	if !strings.HasSuffix(lower, modSuffix) {
		return "unexpected file in mods directory"
	}
	return ""
}

// normalize lowercases, trims and de-duplicates the prohibited suffixes,
// falling back to DefaultProhibited when the input is empty.
func normalize(suffixes []string) []string {
	if len(suffixes) == 0 {
		suffixes = DefaultProhibited
	}

	seen := make(map[string]struct{}, len(suffixes))
	out := make([]string, 0, len(suffixes))
	for _, suffix := range suffixes {
		suffix = strings.ToLower(strings.TrimSpace(suffix))
		if suffix == "" {
			continue
		}
		if _, ok := seen[suffix]; ok {
			continue
		}
		seen[suffix] = struct{}{}
		out = append(out, suffix)
	}
	return out
}

// relative returns path relative to root, falling back to path on error.
func relative(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}
