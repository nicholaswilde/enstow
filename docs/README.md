# :package: enstow :lock:

![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/nicholaswilde/enstow?style=for-the-badge)
[![ci](https://img.shields.io/github/actions/workflow/status/nicholaswilde/enstow/ci.yml?label=ci&style=for-the-badge&branch=main&logo=github-actions)](https://github.com/nicholaswilde/enstow/actions/workflows/ci.yml)
[![Coveralls](https://img.shields.io/coveralls/github/nicholaswilde/enstow/main?style=for-the-badge&logo=coveralls)](https://coveralls.io/github/nicholaswilde/enstow?branch=main)
[![task](https://img.shields.io/badge/Task-Enabled-brightgreen?style=for-the-badge&logo=task&logoColor=white)](https://taskfile.dev/#/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](../LICENSE)

A high-performance, single-binary CLI secret-aware dotfile manager combining GNU [`stow`](https://www.gnu.org/software/stow/) symlinking with seamless [`sops`](https://getsops.io/) and [`age`](https://github.com/FiloSottile/age) decryption.

> [!WARNING]
> This project is currently in a `v0.X.X` development stage. Features and configurations are subject to change, and breaking changes may be introduced at any time.

> [!IMPORTANT]
> Decrypted secret target files are written with strict permissions (`0600` on Unix). Plaintext files must never be stored or committed into version-controlled dotfile repositories.

---

## :rocket:&nbsp; TL;DR

### :floppy_disk:&nbsp; Installation

```bash
# Homebrew
brew install nicholaswilde/homebrew-tap/enstow
```

```powershell
# Scoop (Windows)
scoop bucket add nicholaswilde https://github.com/nicholaswilde/scoop-bucket
scoop install enstow
```

```bash
# Cargo (from source)
cargo install --git https://github.com/nicholaswilde/enstow
```

Debian/Ubuntu `.deb` packages are also published via [`nicholaswilde/apt`](https://nicholaswilde.io/apt) — see [Installation](https://nicholaswilde.io/enstow/installation/).

### :gear:&nbsp; Usage

```bash
# Bootstrap a new machine from a remote dotfiles repository
enstow init https://github.com/username/dotfiles.git

# Preview symlink and secret decryption actions without modifying disk
enstow apply --dry-run

# Apply specific dotfile packages
enstow apply zsh nvim git

# Generate a built-in age identity key (~/.config/sops/age/keys.txt)
enstow keygen

# Ingest an existing secret file into a package encrypted with age
enstow add ~/.secrets/api.env -p secrets --encrypt

# Inspect sync, conflict, and secret drift status (or hide SYNCED rows)
enstow status
enstow status --changes-only

# Audit secret hygiene, permissions, symlink health, or all git-tracked files in CI
enstow doctor
enstow doctor --tracked

# Check for or install the latest GitHub release
enstow self-update --check
```

---

## :book:&nbsp; Documentation

Documentation can be found on the [enstow documentation site](https://nicholaswilde.io/enstow).

---

## :star:&nbsp; Contributing

See [Contributing](https://nicholaswilde.io/enstow/CONTRIBUTING/).

---

## :sparkles:&nbsp; Code of Conduct

See [Code of Conduct](https://nicholaswilde.io/enstow/CODE_OF_CONDUCT/).

---

## :balance_scale:&nbsp; License

[Apache License 2.0](../LICENSE)

---

## :pencil:&nbsp; Author

This project was started in 2026 by [Nicholas Wilde](https://github.com/nicholaswilde/).
