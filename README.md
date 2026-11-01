# enstow

[![task](https://img.shields.io/badge/Task-Enabled-brightgreen?style=for-the-badge&logo=task&logoColor=white)](https://taskfile.dev/#/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](LICENSE)

Secret-aware dotfile manager combining GNU `stow` symlinking with `sops` and `age` decryption.

> [!WARNING]
> This project is currently in a `v0.X.X` development stage. Features and configurations are subject to change, and breaking changes may be introduced at any time.

## Features

- **Symlink Management**: Scans dotfile directories and cleanly links non-secret files into target destination (e.g. `$HOME`).
- **Secret Decryption**: Recognizes encrypted secret files (`.sops.yaml`, `.age`, etc.), decrypts them in memory, and writes plaintext files to the destination with restricted permissions (`0600`).
- **Modular Packages**: Organizes dotfiles into modular packages (e.g. `zsh`, `nvim`, `git`).
- **Unstow & Restow**: Unlink managed dotfiles cleanly or restow packages to prune stale links and re-apply in one step.
- **Status Reporting**: Inspect synced, missing, and conflicting symlinks with optional JSON output.
- **Secret Encryption**: Encrypt secrets directly to `.age` files using age recipient keys or identity files.
- **Ignore Rules**: Filters files using `.enstowignore` or `.stow-local-ignore`.
- **Dry-run Mode**: Previews all symlink and decryption operations before making changes.

## Usage

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

Check sync, missing, or conflicting state for dotfiles:

```bash
# Human-readable status
enstow status

# Status for specific packages
enstow status zsh nvim

# Machine-readable JSON output
enstow status --json
```

### Encrypt Secrets

Encrypt a secret dotfile to `.age`:

```bash
# Encrypt using recipient public key
enstow encrypt config.env -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# Encrypt using identity file to derive recipient
enstow encrypt secret.json --age-key-file ~/.config/sops/age/keys.txt
```

## Development

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
