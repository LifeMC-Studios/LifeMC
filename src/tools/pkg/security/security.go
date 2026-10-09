// Package security scans the payload directories of every active Minecraft
// version for prohibited files and, when requested, removes them.
package security

import (
	"errors"
	"fmt"
	"io"
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
// version's payload directories. It covers known infection vectors across
// Windows, macOS and Linux.
var DefaultProhibited = []string{
	// Executables and scripts.
	".exe", ".bat", ".cmd", ".ps1", ".vbs", ".msi", ".sh", ".command",
	// Dynamic libraries and injectable payloads.
	".dll", ".so", ".dylib",
	// Links and traps.
	".lnk", ".url",
	// Backups and temporary files.
	".jar.bak", ".old", ".tmp",
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

		reason, err := inspect(path, entry, target, prohibited)
		if err != nil {
			return err
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
	if isVersionedLibrary(lower) {
		return "prohibited versioned library"
	}
	if strict && !strings.HasSuffix(lower, modSuffix) {
		return "unexpected file (expected " + modSuffix + ")"
	}
	return ""
}

// isVersionedLibrary reports whether name is a versioned dynamic library such
// as "libfoo.so.1" or "libbar.dylib.1.2".
func isVersionedLibrary(name string) bool {
	return strings.Contains(name, ".so.") || strings.Contains(name, ".dylib.")
}

// inspect returns the reason path is prohibited, or "" when it is acceptable.
// It interdicts symbolic links, non-regular files, hard links, prohibited
// suffixes, unexpected files in strict directories and raw binaries without an
// extension.
func inspect(path string, entry fs.DirEntry, target Target, prohibited []string) (string, error) {
	kind := entry.Type()
	if kind&fs.ModeSymlink != 0 {
		return "symbolic link", nil
	}
	if !kind.IsRegular() {
		return "unexpected non-regular file", nil
	}

	info, err := entry.Info()
	if err != nil {
		return "", fmt.Errorf("security: stat %q: %w", path, err)
	}
	if isHardlink(path, info) {
		return "hard link", nil
	}

	if reason := classify(entry.Name(), target.Strict, prohibited); reason != "" {
		return reason, nil
	}
	if isRawBinary(path, entry.Name()) {
		return "raw binary without extension", nil
	}
	return "", nil
}

// isRawBinary reports whether an extensionless file starts with a known
// executable magic number (ELF, PE or Mach-O).
func isRawBinary(path, name string) bool {
	if filepath.Ext(name) != "" {
		return false
	}
	return hasBinaryMagic(path)
}

// hasBinaryMagic reports whether the file header matches a known executable
// format.
func hasBinaryMagic(path string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	var header [4]byte
	if _, err := io.ReadFull(file, header[:]); err != nil {
		return false
	}
	return binaryMagic(header)
}

// binaryMagic reports whether header matches a known executable magic number.
func binaryMagic(header [4]byte) bool {
	switch {
	case header[0] == 0x7F && header[1] == 'E' && header[2] == 'L' && header[3] == 'F': // ELF
		return true
	case header[0] == 'M' && header[1] == 'Z': // PE
		return true
	case header[0] == 0xFE && header[1] == 0xED && header[2] == 0xFA && (header[3] == 0xCE || header[3] == 0xCF): // Mach-O
		return true
	case header[0] == 0xCE && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE: // Mach-O 32-bit LE
		return true
	case header[0] == 0xCF && header[1] == 0xFA && header[2] == 0xED && header[3] == 0xFE: // Mach-O 64-bit LE
		return true
	case header[0] == 0xCA && header[1] == 0xFE && header[2] == 0xBA && header[3] == 0xBE: // Mach-O fat / Java class
		return true
	}
	return false
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
