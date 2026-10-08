// Package security scans the payload directories of every active Minecraft
// version for prohibited files and, when requested, removes them.
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

// modSuffix is the only file type expected inside a strict packwiz metadata
// directory (mods, resourcepacks).
const modSuffix = ".pw.toml"

// DefaultProhibited lists the file suffixes that must never ship inside a
// version's payload directories.
var DefaultProhibited = []string{
	".exe",
	".bat",
	".sh",
	".jar.bak",
}

// Target describes a version sub-directory inspected by a scan.
type Target struct {
	Name   string // directory name relative to the version root, e.g. "config"
	Strict bool   // when true, only packwiz manifests are expected
}

// DefaultTargets lists the directories scanned inside every version root. mods
// and resourcepacks hold packwiz metadata and are strict; config may hold
// arbitrary configuration files and only rejects prohibited file types.
var DefaultTargets = []Target{
	{Name: "mods", Strict: true},
	{Name: "resourcepacks", Strict: true},
	{Name: "config", Strict: false},
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
	// Targets lists the version sub-directories to inspect. A nil or empty slice
	// falls back to DefaultTargets.
	Targets []Target
}

// targets returns the configured scan targets, falling back to DefaultTargets.
func (o Options) targets() []Target {
	if len(o.Targets) == 0 {
		return DefaultTargets
	}
	return o.Targets
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
	targets := opts.targets()
	logger.Debug("scan start", "roots", len(roots), "dry_run", opts.DryRun, "prohibited", len(prohibited), "targets", len(targets))

	report := &Report{Findings: make([]Finding, 0)}
	for _, root := range roots {
		findings, err := scanRoot(root, prohibited, targets, opts.DryRun)
		if err != nil {
			return nil, err
		}
		report.Findings = append(report.Findings, findings...)
	}

	logger.Debug("scan done", "roots", len(roots), "findings", len(report.Findings))
	return report, nil
}

// scanRoot walks every target directory of a single version root.
func scanRoot(root string, prohibited []string, targets []Target, dryRun bool) ([]Finding, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("security: stat root %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("security: root %q is not a directory", root)
	}

	version := filepath.Base(root)
	findings := make([]Finding, 0)
	for _, target := range targets {
		dir := filepath.Join(root, target.Name)
		exists, err := isDir(dir)
		if err != nil {
			return nil, fmt.Errorf("security: stat %q: %w", dir, err)
		}
		if !exists {
			logger.Debug("target directory absent", "root", root, "target", target.Name)
			continue
		}

		found, err := scanDir(root, version, dir, target, prohibited, dryRun)
		if err != nil {
			return nil, err
		}
		findings = append(findings, found...)
	}
	return findings, nil
}

// scanDir walks a single target directory and returns its findings.
func scanDir(root, version, dir string, target Target, prohibited []string, dryRun bool) ([]Finding, error) {
	findings := make([]Finding, 0)
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}

		reason := classify(entry.Name(), target.Strict, prohibited)
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
		return nil, fmt.Errorf("security: walk %q: %w", dir, err)
	}
	return findings, nil
}

// isDir reports whether path exists and is a directory.
func isDir(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return info.IsDir(), nil
}

// classify returns the reason name is prohibited, or "" when it is acceptable.
// When strict is true only packwiz manifests are expected.
func classify(name string, strict bool, prohibited []string) string {
	lower := strings.ToLower(name)
	for _, suffix := range prohibited {
		if strings.HasSuffix(lower, suffix) {
			return fmt.Sprintf("prohibited file type %q", suffix)
		}
	}
	if strict && !strings.HasSuffix(lower, modSuffix) {
		return "unexpected file (expected " + modSuffix + ")"
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
