// Package validator verifies that every download URL referenced by packwiz
// manifests points to an approved CDN domain.
package validator

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// DefaultAllowlist holds the CDN domains approved for LifeMC mod downloads.
var DefaultAllowlist = []string{
	"cdn.modrinth.com",
	"github.com",
	"raw.githubusercontent.com",
}

// logger tags every record emitted by this package.
var logger = slog.With("module", "validator")

// manifest mirrors the subset of a packwiz TOML that carries download URLs.
type manifest struct {
	Download download    `toml:"download"`
	Files    []fileEntry `toml:"files"`
}

// fileEntry is a packwiz index entry that may embed a download table.
type fileEntry struct {
	Download download `toml:"download"`
}

// download is the packwiz download table.
type download struct {
	URL string `toml:"url"`
}

// urls returns every download URL declared by the manifest.
func (m manifest) urls() []string {
	urls := make([]string, 0, len(m.Files)+1)
	if m.Download.URL != "" {
		urls = append(urls, m.Download.URL)
	}
	for _, file := range m.Files {
		if file.Download.URL != "" {
			urls = append(urls, file.Download.URL)
		}
	}
	return urls
}

// Violation describes a single manifest that failed validation.
type Violation struct {
	File   string // manifest path relative to its root
	Reason string // human-readable explanation
}

// Error renders the violation as "file: reason".
func (v Violation) Error() string {
	return fmt.Sprintf("%s: %s", v.File, v.Reason)
}

// ValidationError aggregates every violation found during a validation run.
type ValidationError struct {
	Violations []Violation
}

// Error lists all violations, one per line.
func (e *ValidationError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d manifest(s) failed validation:", len(e.Violations))
	for _, v := range e.Violations {
		fmt.Fprintf(&b, "\n  - %s", v)
	}
	return b.String()
}

// Validate walks every .toml manifest under roots and reports all download URLs
// whose host is not present in allowlist. It returns nil when every manifest is
// valid; a nil allowlist falls back to DefaultAllowlist.
func Validate(roots, allowlist []string) error {
	if len(roots) == 0 {
		return errors.New("validator: no roots provided")
	}
	if len(allowlist) == 0 {
		allowlist = DefaultAllowlist
	}

	allowed := make(map[string]struct{}, len(allowlist))
	for _, domain := range allowlist {
		allowed[strings.ToLower(domain)] = struct{}{}
	}
	logger.Debug("validate start", "roots", len(roots), "allowlist", len(allowed))

	violations := make([]Violation, 0)
	for _, root := range roots {
		found, err := validateRoot(root, allowed)
		if err != nil {
			return err
		}
		violations = append(violations, found...)
	}

	logger.Debug("validate done", "roots", len(roots), "violations", len(violations))
	if len(violations) == 0 {
		return nil
	}
	return &ValidationError{Violations: violations}
}

// validateRoot walks root and validates every .toml manifest it finds.
func validateRoot(root string, allowed map[string]struct{}) ([]Violation, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("validator: stat root %q: %w", root, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("validator: root %q is not a directory", root)
	}

	violations := make([]Violation, 0)
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".toml") {
			return nil
		}

		found, err := validateFile(root, path, allowed)
		if err != nil {
			return err
		}
		violations = append(violations, found...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("validator: walk %q: %w", root, err)
	}
	return violations, nil
}

// validateFile parses a single manifest and reports its unauthorized domains.
// Unparsable manifests are reported as violations rather than hard errors so a
// single run surfaces every problem.
func validateFile(root, path string, allowed map[string]struct{}) ([]Violation, error) {
	var m manifest
	if _, err := toml.DecodeFile(path, &m); err != nil {
		return []Violation{{File: relative(root, path), Reason: fmt.Sprintf("invalid TOML: %v", err)}}, nil
	}

	file := relative(root, path)
	violations := make([]Violation, 0)
	for _, raw := range m.urls() {
		host, err := hostOf(raw)
		if err != nil {
			violations = append(violations, Violation{File: file, Reason: fmt.Sprintf("invalid URL %q: %v", raw, err)})
			continue
		}
		if _, ok := allowed[host]; ok {
			continue
		}
		violations = append(violations, Violation{File: file, Reason: fmt.Sprintf("unauthorized domain %q in %q", host, raw)})
	}
	return violations, nil
}

// hostOf extracts the lowercased host from a raw URL.
func hostOf(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if parsed.Host == "" {
		return "", errors.New("missing host")
	}
	return strings.ToLower(parsed.Hostname()), nil
}

// relative returns path relative to root, falling back to path on error.
func relative(root, path string) string {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return path
	}
	return rel
}
