# enstow

[![task](https://img.shields.io/badge/Task-Enabled-brightgreen?style=for-the-badge&logo=task&logoColor=white)](https://taskfile.dev/#/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](LICENSE)

Secret-aware dotfile manager combining GNU `stow` symlinking with `sops` and `age` decryption.

> [!WARNING]
> This project is currently in a `v0.X.X` development stage. Features and configurations are subject to change, and breaking changes may be introduced at any time.

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

---

## :balance_scale: License

[Apache License 2.0](LICENSE)

## :writing_hand: Author

​This project was started in 2026 by ​[Nicholas Wilde​](https://github.com/nicholaswilde)
