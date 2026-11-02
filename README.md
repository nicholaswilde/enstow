# :package: enstow :lock:

[![Coveralls](https://img.shields.io/coveralls/github/nicholaswilde/enstow/main?style=for-the-badge&logo=coveralls)](https://coveralls.io/github/nicholaswilde/enstow?branch=main)
[![task](https://img.shields.io/badge/Task-Enabled-brightgreen?style=for-the-badge&logo=task&logoColor=white)](https://taskfile.dev/#/)
<!-- [![ci](https://img.shields.io/github/actions/workflow/status/nicholaswilde/tfa/ci.yml?label=ci&style=for-the-badge&branch=main&logo=github-actions)](https://github.com/nicholaswilde/tfa/actions/workflows/ci.yml) -->
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](LICENSE)

Secret-aware dotfile manager combining GNU `stow` symlinking with `sops` and `age` decryption.

> [!WARNING]
> This project is currently in a `v0.X.X` development stage. Features and configurations are subject to change, and breaking changes may be introduced at any time.

---

## :sparkles: Features

- **Symlink Management**: Scans dotfile directories and cleanly links non-secret files into target destination (e.g. `$HOME`).
- **Secret Decryption**: Recognizes encrypted secret files (`.sops.yaml`, `.age`, etc.), decrypts them in memory, and writes plaintext files to the destination with restricted permissions (`0600`).
- **Modular Packages**: Organizes dotfiles into modular packages (e.g. `zsh`, `nvim`, `git`).
- **Unstow & Restow**: Unlink managed dotfiles cleanly or restow packages to prune stale links and re-apply in one step.
- **Status Reporting**: Inspect synced, missing, conflicting, modified (drifted), and unverified dotfiles with optional JSON output.
- **Secret Encryption & Editing**: Encrypt dotfiles to `.age` files and interactively edit them in `$EDITOR` with automatic in-memory re-encryption.
- **Ignore Rules**: Filters files using `.enstowignore`, `.stow-local-ignore`, `--ignore` / `-i` CLI flags, or `ENSTOW_IGNORE` environment variable.
- **Dry-run Mode**: Previews all symlink and decryption operations before making changes.

---

## :keyboard: Usage

### Apply Dotfiles

Apply all packages or specific packages to target directory (default: `$HOME`):

```bash
# Preview changes across all packages
enstow apply --dry-run

# Apply all dotfiles
enstow apply --source ./dotfiles --target ~

# Apply specific packages
enstow apply zsh nvim tmux
```

### Restow Packages

Clean stale/orphaned symlinks and re-apply packages in one step:

```bash
# Preview restow
enstow restow --dry-run zsh

# Restow target packages
enstow restow zsh nvim
```

### Unstow Dotfiles

Remove symlinks and decrypted secret files managed by enstow:

```bash
# Preview removal
enstow unstow --dry-run zsh

# Unstow specific packages
enstow unstow zsh
```

### Inspect Status

Check sync, missing, conflicting, modified (drifted), or unverified state for dotfiles:

```bash
# Human-readable status
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

### Encrypt Secrets

Encrypt a secret dotfile to `.age`:

```bash
# Encrypt using recipient public key
enstow encrypt config.env -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# Encrypt using identity file to derive recipient
enstow encrypt secret.json --age-key-file ~/.config/sops/age/keys.txt
```

### Edit Secrets

Interactively decrypt, edit in `$ENSTOW_EDITOR` (or `$VISUAL` / `$EDITOR`), and re-encrypt an `.age` file:

```bash
# Edit using default editor ($ENSTOW_EDITOR / $VISUAL / $EDITOR / system fallback)
enstow edit secret.env.age

# Edit using explicit key file
enstow edit secret.env.age --age-key-file ~/.config/sops/age/keys.txt

# Edit using specific editor command
enstow edit secret.env.age --editor "nano"
```

### Ignore Patterns

Ignore specific files or patterns during dotfile operations using CLI flags, environment variables, or config files:

```bash
# Ignore patterns via CLI flags
enstow apply -i "*.bak" -i "*.tmp"

# Ignore patterns via environment variable (comma or colon separated)
export ENSTOW_IGNORE="*.bak,*.tmp:*.swp"
enstow apply
```

### Configuration File

`enstow` supports configuration files in TOML, YAML, or JSON. By default, it looks for `$XDG_CONFIG_HOME/enstow/config.{toml,yaml,yml,json}` (fallback `~/.config/enstow/...`). Pass `--config <path>` / `-C <path>` or set `ENSTOW_CONFIG` to override.

See [assets/config.example.toml](assets/config.example.toml) for an example template.

**Precedence Order:**

1. CLI Arguments (`--source`, `--target`, `--dry-run`, `--force`, `--backup` / `-b`, `--backup-dir`, `--prune`, `--age-key-file`, `--recipient`, `--editor`, `--ignore` / `-i`, `--json`)
2. Environment Variables (`ENSTOW_SOURCE`, `ENSTOW_TARGET`, `ENSTOW_DRY_RUN`, `ENSTOW_FORCE`, `ENSTOW_BACKUP`, `ENSTOW_BACKUP_DIR`, `ENSTOW_PRUNE`, `ENSTOW_AGE_KEY_FILE` / `SOPS_AGE_KEY_FILE`, `ENSTOW_RECIPIENTS` / `SOPS_AGE_RECIPIENTS`, `ENSTOW_PACKAGES`, `ENSTOW_IGNORE`, `ENSTOW_EDITOR` / `VISUAL` / `EDITOR`, `ENSTOW_JSON`)
3. Configuration File (`config.{toml,yaml,json}`)
4. Built-in Defaults

*Note: Ignore patterns from CLI arguments, `ENSTOW_IGNORE`, and configuration files merge additively without duplicates.*

---

## :test_tube: Development & Quality Gates

```bash
# Check code
task check

# Format & Lint
task fmt
task lint

# Run tests
task test
```

---

## :balance_scale: License

[Apache License 2.0](LICENSE)

## :writing_hand: Author

​This project was started in 2026 by ​[Nicholas Wilde​](https://github.com/nicholaswilde)
