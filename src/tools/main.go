// Command lifemc-cli is the LifeMC modpack maintenance CLI.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"lifemc-cli/pkg/scanner"
	"lifemc-cli/pkg/ui"
)

// logger tags every record emitted by the CLI entrypoint.
var logger = slog.With("module", "cli")

// usageError marks a malformed invocation; main maps it to exit code 2.
type usageError struct{ msg string }

// Error implements the error interface.
func (e usageError) Error() string { return e.msg }

// usagef builds a usageError from a format string.
func usagef(format string, args ...any) error {
	return usageError{msg: fmt.Sprintf(format, args...)}
}

// session carries the resolved source root and the discovered versions.
type session struct {
	root     string
	versions []scanner.Version
}

// roots returns the absolute path of every discovered version.
func (s session) roots() []string {
	roots := make([]string, len(s.versions))
	for i, version := range s.versions {
		roots[i] = version.Path
	}
	return roots
}

// scoped returns a session restricted to the version named name, or the full
// session when name is empty. An unknown name is a usage error.
func (s session) scoped(name string) (session, error) {
	if name == "" {
		return s, nil
	}
	for _, version := range s.versions {
		if version.Name == name {
			return session{root: s.root, versions: []scanner.Version{version}}, nil
		}
	}
	return session{}, usagef("version %q not found (active: %s)", name, strings.Join(s.versionNames(), ", "))
}

// versionNames returns the name of every discovered version.
func (s session) versionNames() []string {
	names := make([]string, len(s.versions))
	for i, version := range s.versions {
		names[i] = version.Name
	}
	return names
}

// command is a single CLI action.
type command struct {
	name  string
	usage string
	run   func(ctx context.Context, s session, args []string) error
}

// commands lists every supported action in help order.
var commands = []command{
	{name: "versions", usage: "list every active Minecraft version", run: runVersions},
	{name: "validate", usage: "check download URLs against the CDN allowlist", run: runValidate},
	{name: "scan", usage: "scan payload directories for prohibited files (--version <name>, --apply)", run: runScan},
	{name: "verify", usage: "run validate and scan as a single read-only gate", run: runVerify},
	{name: "update", usage: "update every external file via packwiz", run: runUpdate},
	{name: "export", usage: "export versions as Modrinth .mrpack (--version <name>)", run: runExport},
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		var usage usageError
		if errors.As(err, &usage) {
			fmt.Fprintln(os.Stderr, ui.Report("Usage error", ui.StatusError, usage.Error(), nil))
			os.Exit(2)
		}
		slog.Error("command failed", "error", err)
		os.Exit(1)
	}
}

// run resolves the source root, discovers versions and dispatches the command.
func run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		printUsage()
		return usagef("no command provided")
	}

	name := args[0]
	if name == "help" || name == "-h" || name == "--help" {
		printUsage()
		return nil
	}

	cmd, ok := lookup(name)
	if !ok {
		return usagef("unknown command %q (want: %s)", name, commandNames())
	}

	s, err := newSession()
	if err != nil {
		return err
	}

	logger.Debug("dispatch", "command", name, "versions", len(s.versions))
	return cmd.run(ctx, s, args[1:])
}

// newSession resolves the source root and discovers every active version.
func newSession() (session, error) {
	wd, err := os.Getwd()
	if err != nil {
		return session{}, fmt.Errorf("resolve working directory: %w", err)
	}

	root, err := scanner.ResolveRoot(wd)
	if err != nil {
		return session{}, err
	}

	versions, err := scanner.Discover(root)
	if err != nil {
		return session{}, err
	}
	return session{root: root, versions: versions}, nil
}

// lookup finds a command by name.
func lookup(name string) (command, bool) {
	for _, cmd := range commands {
		if cmd.name == name {
			return cmd, true
		}
	}
	return command{}, false
}

// commandNames returns the comma-separated list of supported commands.
func commandNames() string {
	names := make([]string, len(commands))
	for i, cmd := range commands {
		names[i] = cmd.name
	}
	return strings.Join(names, ", ")
}

// printUsage writes the branded command list to stdout.
func printUsage() {
	fmt.Println(ui.Banner())
	fmt.Println(ui.Subtle("LifeMC Studios · modpack maintenance CLI"))
	fmt.Println()

	lines := make([]string, 0, len(commands))
	for _, cmd := range commands {
		lines = append(lines, ui.Strong(fmt.Sprintf("%-9s", cmd.name))+"  "+ui.Subtle(cmd.usage))
	}
	fmt.Println(ui.Box("Commands", lines))
	fmt.Println(ui.Subtle("Usage: lifemc-cli <command> [flags]"))
}
