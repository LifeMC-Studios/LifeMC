# lifemc-cli — Usage

Maintenance CLI for the LifeMC modpack. It discovers every active Minecraft
version under `src/` and runs the requested routine across all of them.

Run it from anywhere inside the `src/` tree; the CLI walks up to locate the
source root automatically. The practical entry point is the module directory:

```sh
cd src/tools
go run . <command> [flags]
```

## Commands

| Command    | Usage                       | Description                                                        |
| ---------- | --------------------------- | ------------------------------------------------------------------ |
| `versions` | `lifemc-cli versions`       | List every active version with its `packwiz`/`mods` flags.         |
| `validate` | `lifemc-cli validate`       | Check every manifest download URL against the CDN allowlist.       |
| `scan`     | `lifemc-cli scan [flags]`   | Scan payload directories for prohibited files; dry-run by default. |
| `verify`   | `lifemc-cli verify`         | Read-only gate: run `validate` and `scan` together.                |
| `update`   | `lifemc-cli update`         | Update every external file via `packwiz update --all -y`.          |
| `export`   | `lifemc-cli export [flags]` | Verify, then export versions as Modrinth `.mrpack` (fail-closed).  |
| `help`     | `lifemc-cli help`           | Print the command list. Aliases: `-h`, `--help`.                   |

`versions`, `validate`, `verify` and `update` are global and take no flags.
`update` and `export` skip versions without a `pack.toml` and log a warning.

## Flags

`scan` and `export` accept a version selector; only `scan` accepts the
deletion flags.

| Flag                            | Commands         | Effect                                                          |
| ------------------------------- | ---------------- | --------------------------------------------------------------- |
| `--version <name>`, `-v <name>` | `scan`, `export` | Scope the command to a single version, e.g. `1.21.11`.          |
| `--dry-run`                     | `scan`           | Report prohibited files without deleting them. **Default.**     |
| `--apply`                       | `scan`           | Delete every flagged file (the command still fails, see below). |

Flags are evaluated left to right, so for repeated flags the last one wins
(`scan --apply --dry-run` ends up in dry-run mode). An unknown flag or a
missing flag value is a usage error, as is an unknown `--version` name.

## Scanned directories

`scan`, `verify` inspect every version sub-directory listed in
`security.DefaultTargets`:

| Directory        | Mode   | Expectation                                                             |
| ---------------- | ------ | ----------------------------------------------------------------------- |
| `mods/`          | strict | Only packwiz `*.pw.toml` manifests are allowed.                         |
| `resourcepacks/` | strict | Only packwiz `*.pw.toml` manifests are allowed.                         |
| `config/`        | loose  | Arbitrary config files are allowed; only prohibited types are rejected. |

Prohibited file types default to the known infection vectors across Windows,
macOS and Linux:

| Category                        | Suffixes                                                          |
| ------------------------------- | ----------------------------------------------------------------- |
| Executables and scripts         | `.exe`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.msi`, `.sh`, `.command` |
| Dynamic libraries / injectables | `.dll`, `.so`, `.dylib`                                           |
| Links and traps                 | `.lnk`, `.url`                                                    |
| Backups and temporary files     | `.jar.bak`, `.old`, `.tmp`                                        |

Beyond suffixes, the scanner also interdicts, recursively:

- **Raw binaries without an extension** — detected by magic number (ELF, PE, Mach-O).
- **Symbolic links** — every symlink is flagged, regardless of target.
- **Hard links** — any file with more than one link (Unix `nlink`, Windows
  `NumberOfLinks`).
- **Non-regular files** — FIFOs, sockets and device nodes.
- **Unexpected files** in strict directories (anything but `*.pw.toml`).

## Manifest validation

`validate`, `verify` and `export` reject, in every `pack.toml`/`*.pw.toml`:

- Download URLs whose host is not in the CDN allowlist (`validator.DefaultAllowlist`).
- **Raw IP-based URLs** (e.g. `http://192.168.1.10/payload.jar`).
- **Directory traversal** in declared `file` paths (absolute paths or `..` segments).

## Exit codes

| Code | Meaning                                                                                      |
| ---- | -------------------------------------------------------------------------------------------- |
| `0`  | Success.                                                                                     |
| `1`  | Runtime failure: findings, validation violations, or a failed operation.                     |
| `2`  | Usage error: unknown command, unknown flag, missing flag value, or unknown `--version` name. |

`scan` exits `1` whenever it detects a prohibited file, in **both** dry-run and
`--apply` mode: the scanner blocks explicitly and treats automated deletion as a
secondary cleanup, never as a silent success. `verify` exits `1` on any manifest
violation or prohibited file. `export` is **fail-closed**: it runs the same
gate first and aborts with exit `1` before invoking `packwiz` when anything is
wrong. This makes `scan`, `verify` and `export` usable as CI gates.

## Examples

```sh
cd src/tools

# Inventory of active versions.
go run . versions

# Verify the CDN allowlist across every manifest.
go run . validate

# Security sweep without touching the tree.
go run . scan

# Security sweep scoped to one version (long and short flags).
go run . scan --version 1.21.11
go run . scan -v 1.18.2

# Remove every prohibited file found (still exits 1 on findings).
go run . scan --apply

# Full read-only gate (validate + scan); fails on any finding.
go run . verify

# Refresh all mods across every version.
go run . update

# Build a Modrinth .mrpack for every version, or a single one.
# Export verifies first and aborts (exit 1) on any anomaly.
go run . export
go run . export --version 1.21.11
```

## Requirements

- Go 1.27+ to build and run.
- `packwiz` on `PATH` for `update` and `export` (installed by the devcontainer).
