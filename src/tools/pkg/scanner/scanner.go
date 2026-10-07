// Package scanner discovers the active Minecraft version directories that live
// inside the LifeMC source tree.
package scanner

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// toolsDir is the CLI directory that must never be treated as a version.
const toolsDir = "tools"

// versionPattern matches Minecraft release identifiers such as "1.18.2" or "1.21".
var versionPattern = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)

// ErrNoVersions is returned when the source root holds no active version.
var ErrNoVersions = errors.New("scanner: no active Minecraft version found")

// logger tags every record emitted by this package.
var logger = slog.With("module", "scanner")

// Version describes a discovered Minecraft version directory.
type Version struct {
	Name       string // directory name, e.g. "1.21.11"
	Path       string // absolute path to the version directory
	HasPackwiz bool   // a packwiz manifest (pack.toml) is present
	HasMods    bool   // a mods directory is present
}

// Discover walks root and returns every active Minecraft version directory,
// sorted by version. The tools directory and any non-version directory are
// ignored.
func Discover(root string) ([]Version, error) {
	if root == "" {
		return nil, errors.New("scanner: root path is empty")
	}
	logger.Debug("discover start", "root", root)

	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("scanner: read root %q: %w", root, err)
	}

	versions := make([]Version, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == toolsDir {
			continue
		}
		if !versionPattern.MatchString(entry.Name()) {
			continue
		}

		version, active, err := inspect(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		if !active {
			continue
		}
		versions = append(versions, version)
	}

	if len(versions) == 0 {
		return nil, ErrNoVersions
	}

	sort.Slice(versions, func(i, j int) bool {
		return compareVersions(versions[i].Name, versions[j].Name) < 0
	})
	logger.Debug("discover done", "root", root, "versions", len(versions))
	return versions, nil
}

// ResolveRoot walks up from start until it finds the LifeMC source directory:
// a directory named "src" that holds at least one version directory.
func ResolveRoot(start string) (string, error) {
	if start == "" {
		return "", errors.New("scanner: start path is empty")
	}

	dir, err := filepath.Abs(start)
	if err != nil {
		return "", fmt.Errorf("scanner: resolve %q: %w", start, err)
	}
	logger.Debug("resolve root start", "start", dir)

	for {
		if filepath.Base(dir) == "src" && containsVersion(dir) {
			logger.Debug("resolve root done", "root", dir)
			return dir, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("scanner: source root not found above %q", start)
		}
		dir = parent
	}
}

// inspect reports whether dir is an active version directory and, if so,
// describes its packwiz and mods configuration.
func inspect(dir string) (Version, bool, error) {
	hasPackwiz, err := fileExists(filepath.Join(dir, "pack.toml"))
	if err != nil {
		return Version{}, false, err
	}

	hasMods, err := dirExists(filepath.Join(dir, "mods"))
	if err != nil {
		return Version{}, false, err
	}

	if !hasPackwiz && !hasMods {
		return Version{}, false, nil
	}

	return Version{
		Name:       filepath.Base(dir),
		Path:       dir,
		HasPackwiz: hasPackwiz,
		HasMods:    hasMods,
	}, true, nil
}

// containsVersion reports whether dir directly holds a version directory.
func containsVersion(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() && versionPattern.MatchString(entry.Name()) {
			return true
		}
	}
	return false
}

// fileExists reports whether path exists and is a regular file.
func fileExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("scanner: stat %q: %w", path, err)
	}
	return !info.IsDir(), nil
}

// dirExists reports whether path exists and is a directory.
func dirExists(path string) (bool, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("scanner: stat %q: %w", path, err)
	}
	return info.IsDir(), nil
}

// compareVersions orders two dotted version strings numerically.
func compareVersions(a, b string) int {
	left, right := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(left) && i < len(right); i++ {
		x, _ := strconv.Atoi(left[i])
		y, _ := strconv.Atoi(right[i])
		if x != y {
			return x - y
		}
	}
	return len(left) - len(right)
}
