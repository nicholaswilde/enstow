# :package: enstow :lock:

[![Coveralls](https://img.shields.io/coveralls/github/nicholaswilde/enstow/main?style=for-the-badge&logo=coveralls)](https://coveralls.io/github/nicholaswilde/enstow?branch=main)
[![task](https://img.shields.io/badge/Task-Enabled-brightgreen?style=for-the-badge&logo=task&logoColor=white)](https://taskfile.dev/#/)
[![ci](https://img.shields.io/github/actions/workflow/status/nicholaswilde/enstow/ci.yml?label=ci&style=for-the-badge&branch=main&logo=github-actions)](https://github.com/nicholaswilde/enstow/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](LICENSE)

A high-performance, single-binary CLI secret-aware dotfile manager combining GNU `stow` symlinking with seamless `sops` and `age` decryption.

> [!WARNING]
> This project is currently in a `v0.X.X` development stage. Features and configurations are subject to change, and breaking changes may be introduced at any time.

> [!IMPORTANT]
> Decrypted secret target files are written with strict permissions (`0600` on unix). Plaintext files must never be stored or committed into version-controlled dotfile repositories.

---

## :sparkles: Features

- **Symlink Management:** Scans dotfile directories and cleanly links non-secret files into target destination (default: `$HOME`).
- **Secret Decryption:** Recognizes encrypted secret files (`.sops.yaml`, `.age`, etc.), decrypts them in memory, and writes plaintext files to the destination with restricted permissions (`0600`).
- **Modular Packages:** Organizes dotfiles into modular packages (e.g. `zsh`, `nvim`, `git`).
- **Unstow & Restow:** Unlink managed dotfiles cleanly or restow packages to prune stale links and re-apply in one step.
- **Collision & Backup Handling:** Detects conflicts with existing target files, with options to preview (`--dry-run`), overwrite (`--force`), or relocate conflicting files to a backup directory (`--backup`, `--backup-dir`).
- **Stale Link Pruning:** Automatically detects and removes orphaned symlinks from previous package versions during apply (`--prune`).
- **Status Reporting:** Inspect synced, missing, conflicting, modified (drifted), and unverified dotfiles with optional JSON output (`--json`).
- **Secret Encryption & Editing:** Encrypt dotfiles to `.age` files and interactively edit them in `$ENSTOW_EDITOR` (or `$VISUAL` / `$EDITOR`) with automatic in-memory re-encryption.
- **Ignore Rules:** Filters files using `.enstowignore`, `.stow-local-ignore`, `--ignore` / `-i` CLI flags, or `ENSTOW_IGNORE` environment variable.
- **Dynamic Shell Completions:** Dynamic shell completion across Bash, Zsh, Fish, PowerShell, and Elvish via `clap_complete`.
- **Lightweight & Portable:** Static, zero-fluff binary written in Rust for Linux, macOS, and Windows.

---

## :rocket: Installation & Build

### Homebrew

Install `enstow` via [Homebrew](https://brew.sh/) using the [nicholaswilde/homebrew-tap](https://github.com/nicholaswilde/homebrew-tap):

```bash
brew install nicholaswilde/homebrew-tap/enstow
```

Or tap the repository first:

```bash
brew tap nicholaswilde/homebrew-tap
brew install enstow
```

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (1.88+)
- [Task](https://taskfile.dev/) (optional, recommended)

### Build Locally

```bash
task build:local
# Or directly with Cargo:
cargo build --release
```

The compiled binary will be placed at `target/release/enstow`.

---

## :keyboard: Usage

```bash
enstow [OPTIONS] [COMMAND]
```

When executed without a subcommand (`enstow`), it runs the default `apply` command with common options.

### Commands

| Command | Description | Example |
| :--- | :--- | :--- |
| `apply` | Symlink regular files and decrypt secret files to target destination | `enstow apply [PACKAGES...]` |
| `restow` | Clean stale symlinks/secrets and re-apply packages in one step | `enstow restow [PACKAGES...]` |
| `unstow` | Remove symlinks and decrypted secret files managed by enstow | `enstow unstow [PACKAGES...]` |
| `status` | Inspect sync, missing, conflict, modified (drift), and unverified state | `enstow status [--json]` |
| `encrypt` | Encrypt a secret dotfile into `.age` format | `enstow encrypt <file> [-r <key>]` |
| `edit` | Interactively decrypt, edit in `$EDITOR`, and re-encrypt an age secret file | `enstow edit <file.age>` |
| `completions` | Output dynamic or static shell completion script (`bash`, `zsh`, `fish`, `powershell`, `elvish`) | `enstow completions zsh [--static]` |
| `man` | Output UNIX roff man page | `enstow man > assets/enstow.1` |

### Applying Dotfiles

Apply all packages or specific packages to target directory (default: `$HOME`):

```bash
# Preview changes across all packages without writing to disk
enstow apply --dry-run
# Or shorter flag:
enstow apply -n

# Apply all dotfiles from custom source to custom target
enstow apply --source ./dotfiles --target ~

# Apply specific packages only
enstow apply zsh nvim tmux

# Overwrite existing conflicting files or differing symlinks
enstow apply --force zsh

# Backup conflicting target files to ~/.enstow-backup before overwriting
enstow apply --backup zsh
enstow apply -b --backup-dir ~/.dotfiles-backup zsh

# Prune stale symlinks no longer present in source packages
enstow apply --prune zsh
```

### Restowing Packages

Clean stale/orphaned symlinks and re-apply packages in one step:

```bash
# Preview restow
enstow restow --dry-run zsh

# Restow target packages
enstow restow zsh nvim
```

### Unstowing Dotfiles

Remove symlinks and decrypted secret files managed by enstow:

```bash
# Preview removal
enstow unstow --dry-run zsh

# Unstow specific packages
enstow unstow zsh nvim
```

### Inspecting Status

Check sync, missing, conflicting, modified (drifted), or unverified state for dotfiles:

```bash
# Human-readable status overview
enstow status

# Status with explicit age key for secret drift verification
enstow status --age-key-file ~/.config/sops/age/keys.txt

# Status for specific packages
enstow status zsh nvim

# Machine-readable JSON output (can also be enabled via ENSTOW_JSON=1 or json = true in config)
enstow status --json
```

States reported:

- `SYNCED`: Symlink points to valid source, or target plaintext matches decrypted secret.
- `MISSING`: Source dotfile exists, but target file does not yet exist.
- `CONFLICT`: Target file exists as unmanaged file, incorrect symlink, or directory.
- `MODIFIED`: Target secret file exists, but content has drifted from the decrypted source.
- `UNVERIFIED`: Target secret file exists, but decryption keys are missing or unavailable.

### Conflict Resolution & Backups

When a target destination already exists with different content or unmanaged files:

- **Dry-run (`-n`, `--dry-run`):** Previews what actions would occur without touching disk.
- **Force (`-f`, `--force`):** Overwrites conflicting target files or replaces differing symlinks.
- **Backup (`-b`, `--backup`):** Relocates colliding destination files out of the way before creating the new link or secret.
- **Backup Directory (`--backup-dir <path>`):** Sets custom destination for backups (defaults to `$TARGET/.enstow-backup`).

```bash
# Safely apply with backup
enstow apply -b --backup-dir ~/backup-dir zsh
```

### Pruning Stale Symlinks

When removing or renaming files in your dotfiles repository, stale links may remain in your target directory:

```bash
# Automatically remove broken or orphaned symlinks for managed packages during apply
enstow apply --prune zsh

# Preview pruning actions
enstow apply --prune --dry-run zsh
```

### Encrypting Secrets

Encrypt a plaintext dotfile into an `.age` encrypted file:

```bash
# Encrypt using explicit recipient public key
enstow encrypt config.env -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# Encrypt using identity file to derive recipient
enstow encrypt secret.json --age-key-file ~/.config/sops/age/keys.txt

# Specify custom output path (defaults to <file>.age)
enstow encrypt secret.json -o secret.json.age -r age1ql3z...
```

### Editing Secrets

Interactively decrypt, edit in `$ENSTOW_EDITOR` (or `$VISUAL` / `$EDITOR`), and re-encrypt an `.age` file in memory:

```bash
# Edit using default editor ($ENSTOW_EDITOR / $VISUAL / $EDITOR / system fallback)
enstow edit secret.env.age

# Edit using explicit key file
enstow edit secret.env.age --age-key-file ~/.config/sops/age/keys.txt

# Edit using specific editor command
enstow edit secret.env.age --editor "nano"
```

### Ignore Rules

Ignore specific files or patterns during dotfile operations:

1. **Package Ignore File:** Create `.enstowignore` or `.stow-local-ignore` inside a package root.
2. **CLI Flags:** Pass `-i` / `--ignore` multiple times.
3. **Environment Variable:** Set `ENSTOW_IGNORE` (comma or colon separated).
4. **Configuration File:** Specify `ignore = ["*.tmp", ".DS_Store"]`.

```bash
# Ignore patterns via CLI flags
enstow apply -i "*.bak" -i "*.tmp"

# Ignore patterns via environment variable
export ENSTOW_IGNORE="*.bak,*.tmp:*.swp"
enstow apply
```

---

## :books: Shell Completions

`enstow` features dynamic autocompletion for commands, options, and packages. Shell scripts can be generated for Bash, Zsh, Fish, PowerShell, and Elvish:

### Bash

```bash
# Add to ~/.bashrc for interactive sessions:
eval "$(enstow completions bash)"

# Or install to standard completion directory:
enstow completions bash > ~/.local/share/bash-completion/completions/enstow
```

### Zsh

```bash
# Add to ~/.zshrc (after compinit):
source <(enstow completions zsh)

# Or save to your fpath directory:
enstow completions zsh > ~/.zfunc/_enstow
# (Ensure fpath includes ~/.zfunc and autoload -Uz compinit && compinit is called)
```

### Fish

```fish
# Save to standard fish completion directory:
enstow completions fish > ~/.config/fish/completions/enstow.fish

# Or load directly in current session:
enstow completions fish | source
```

### PowerShell

```powershell
# Append to your PowerShell profile:
enstow completions powershell >> $PROFILE

# Or load into active session:
enstow completions powershell | Out-String | Invoke-Expression
```

### Elvish

```elvish
# Append to your Elvish rc:
enstow completions elvish >> ~/.elvish/rc.elv

# Or load into active session:
eval (enstow completions elvish | slurp)
```

> [!TIP]
> Dynamic completions automatically service arguments and options on `<TAB>` via `clap_complete`. Pass `--static` to `enstow completions` to generate static fallback completion scripts instead.

Pre-generated completion scripts are also available in the [`completions/`](completions/) folder.

---

## :gear: Configuration

`enstow` supports optional configuration files in **TOML**, **YAML**, or **JSON** format. A fully commented template documenting all supported options and defaults is provided in [`assets/config.example.toml`](assets/config.example.toml).

To quickly initialize configuration from the template:

```bash
mkdir -p ~/.config/enstow
cp assets/config.example.toml ~/.config/enstow/config.toml
```

### Hierarchical Precedence

Settings resolve in strict hierarchical precedence order (highest to lowest):

1. **Command Line Arguments** (e.g. `--source`, `--target`, `--dry-run`, `--force`, `--backup`, `--backup-dir`, `--prune`, `--age-key-file`, `--recipient`, `--editor`, `--ignore`, `--json`, `--log-level`)
2. **Environment Variables** (e.g. `ENSTOW_SOURCE`, `ENSTOW_TARGET`, `ENSTOW_DRY_RUN`, `ENSTOW_FORCE`, `ENSTOW_BACKUP`, `ENSTOW_BACKUP_DIR`, `ENSTOW_PRUNE`, `ENSTOW_AGE_KEY_FILE`, `ENSTOW_RECIPIENTS`, `ENSTOW_PACKAGES`, `ENSTOW_IGNORE`, `ENSTOW_EDITOR`, `ENSTOW_JSON`, `ENSTOW_LOG_LEVEL`)
3. **Configuration File** (`-C <path>` / `--config <path>`, or default locations: `~/.config/enstow/config.{toml,yaml,yml,json}`)
4. **Built-in Defaults** (`source = "."`, `target = "$HOME"`, `dry_run = false`, `force = false`, `backup = false`, `backup_dir = "$target/.enstow-backup"`, `prune = false`, `json = false`, `log_level = "info"`)

> [!NOTE]
> Ignore patterns from CLI arguments, `ENSTOW_IGNORE`, and configuration files merge additively without duplicates.

### Example Configuration Files

#### TOML (`~/.config/enstow/config.toml`)

```toml
source = "~/dotfiles"
target = "~"
dry_run = false
force = false
backup = false
backup_dir = "~/.enstow-backup"
prune = true
age_key_file = "~/.config/sops/age/keys.txt"
recipients = [
  "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
]
packages = ["zsh", "nvim", "git"]
editor = "nvim"
ignore = ["*.tmp", ".DS_Store", "*.swp"]
json = false
log_level = "info"
```

#### YAML (`~/.config/enstow/config.yaml`)

```yaml
source: ~/dotfiles
target: ~
dry_run: false
force: false
backup: false
backup_dir: ~/.enstow-backup
prune: true
age_key_file: ~/.config/sops/age/keys.txt
recipients:
  - age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
packages:
  - zsh
  - nvim
  - git
editor: nvim
ignore:
  - "*.tmp"
  - ".DS_Store"
  - "*.swp"
json: false
log_level: info
```

#### JSON (`~/.config/enstow/config.json`)

```json
{
  "source": "~/dotfiles",
  "target": "~",
  "dry_run": false,
  "force": false,
  "backup": false,
  "backup_dir": "~/.enstow-backup",
  "prune": true,
  "age_key_file": "~/.config/sops/age/keys.txt",
  "recipients": [
    "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
  ],
  "packages": [
    "zsh",
    "nvim",
    "git"
  ],
  "editor": "nvim",
  "ignore": [
    "*.tmp",
    ".DS_Store",
    "*.swp"
  ],
  "json": false,
  "log_level": "info"
}
```

### Environment Variables Reference

| Variable | Config Option | CLI Flag | Description | Default |
| :--- | :--- | :--- | :--- | :--- |
| `ENSTOW_CONFIG` | N/A | `-C`, `--config` | Custom path to configuration file (`.toml`, `.yaml`, `.json`) | `~/.config/enstow/config.*` |
| `ENSTOW_SOURCE` | `source` | `-s`, `--source` | Source directory containing dotfiles packages | `.` |
| `ENSTOW_TARGET` | `target` | `-t`, `--target` | Destination target directory | `$HOME` |
| `ENSTOW_DRY_RUN` | `dry_run` | `-n`, `--dry-run` | Preview actions without disk modifications (`true`/`false`) | `false` |
| `ENSTOW_FORCE` | `force` | `-f`, `--force` | Overwrite conflicting destination files (`true`/`false`) | `false` |
| `ENSTOW_BACKUP` | `backup` | `-b`, `--backup` | Move colliding destination files to backup directory (`true`/`false`) | `false` |
| `ENSTOW_BACKUP_DIR` | `backup_dir` | `--backup-dir` | Path to directory where conflicting files are relocated | `$TARGET/.enstow-backup` |
| `ENSTOW_PRUNE` | `prune` | `--prune` | Prune stale managed symlinks during apply (`true`/`false`) | `false` |
| `ENSTOW_AGE_KEY_FILE` / `SOPS_AGE_KEY_FILE` | `age_key_file` | `--age-key-file` | Path to age identity key file for encryption/decryption | None |
| `ENSTOW_RECIPIENTS` / `SOPS_AGE_RECIPIENTS` | `recipients` | `-r`, `--recipient` | Age recipient public keys for encryption | None |
| `ENSTOW_PACKAGES` | `packages` | `PACKAGES` | Default packages to stow when none specified | None |
| `ENSTOW_IGNORE` | `ignore` | `-i`, `--ignore` | Additional glob patterns to ignore (comma or colon separated) | None |
| `ENSTOW_EDITOR` / `VISUAL` / `EDITOR` | `editor` | `--editor` | Editor command for interactive secret editing (`enstow edit`) | `nano` |
| `ENSTOW_JSON` | `json` | `--json` | Emit status output in JSON format (`true`/`false`) | `false` |
| `ENSTOW_LOG_LEVEL` | `log_level` | `--log-level` | Log filter level (`trace`, `debug`, `info`, `warn`, `error`, `off`) | `info` |

---

## :page_facing_up: Man Page

Generate or view the UNIX man page:

```bash
# Generate man page
task man
# Or with binary
enstow man > assets/enstow.1

# Preview formatted man page
man -l assets/enstow.1
```

---

## :test_tube: Development & Quality Gates

Use `task` as the primary command runner:

```bash
task check        # Type check code
task test         # Run formatting, clippy lints, and unit tests
task test:ci      # Run full suite using CI profile
task lint         # Run clippy with -D warnings
task fmt          # Auto-format with rustfmt
task completions  # Generate shell completion scripts
task man          # Generate UNIX roff man page
task coverage     # Run tests and output coverage summary
task build        # Build all multi-arch Linux targets via cross
```

---

## :balance_scale: License

[Apache License 2.0](LICENSE)

## :writing_hand: Author

​This project was started in 2026 by ​[Nicholas Wilde​](https://github.com/nicholaswilde)
