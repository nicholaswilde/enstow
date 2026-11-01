# enstow

Secret-aware dotfile manager combining GNU `stow` symlinking with `sops` and `age` decryption.

## Features

- **Symlink Management**: Scans dotfile directories and cleanly links non-secret files into target destination (e.g. `$HOME`).
- **Secret Decryption**: Recognizes encrypted secret files (`.sops.yaml`, `.age`, etc.), decrypts them in memory, and writes plaintext files to the destination with restricted permissions (`0600`).
- **Dry-run Mode**: Previews all symlink and decryption operations before making changes.

## Usage

```bash
# Dry-run preview
enstow apply --dry-run

# Apply dotfiles to target (default: $HOME)
enstow apply --source ./dotfiles --target ~
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
