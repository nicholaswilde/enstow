# enstow

![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/nicholaswilde/enstow?style=for-the-badge)
[![ci](https://img.shields.io/github/actions/workflow/status/nicholaswilde/enstow/ci.yml?label=ci&style=for-the-badge&branch=main&logo=github-actions)](https://github.com/nicholaswilde/enstow/actions/workflows/ci.yml)
[![Coveralls](https://img.shields.io/coveralls/github/nicholaswilde/enstow/main?style=for-the-badge&logo=coveralls)](https://coveralls.io/github/nicholaswilde/enstow?branch=main)
[![task](https://img.shields.io/badge/Task-Enabled-brightgreen?style=for-the-badge&logo=task&logoColor=white)](https://taskfile.dev/#/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg?style=for-the-badge)](https://github.com/nicholaswilde/enstow/blob/main/LICENSE)

A high-performance, single-binary CLI secret-aware dotfile manager combining GNU [`stow`](https://www.gnu.org/software/stow/) symlinking with seamless [`sops`](https://getsops.io/) and [`age`](https://github.com/FiloSottile/age) decryption.

!!! warning
    This project is currently in a `v0.X.X` development stage. Features and configurations are subject to change, and breaking changes may be introduced at any time.

!!! important
    Decrypted secret target files are written with strict permissions (`0600` on Unix). Plaintext files must never be stored or committed into version-controlled dotfile repositories.

## :rocket: TL;DR

### :floppy_disk: Installation

=== "Homebrew"

    ```bash
    brew install nicholaswilde/homebrew-tap/enstow
    ```

=== "APT"

    ```bash
    # After adding https://nicholaswilde.io/apt (see Installation page)
    sudo apt update && sudo apt install enstow
    ```

=== "Scoop"

    ```powershell
    scoop bucket add nicholaswilde https://github.com/nicholaswilde/scoop-bucket
    scoop install enstow
    ```

=== "Cargo"

    ```bash
    cargo install --git https://github.com/nicholaswilde/enstow
    ```

### :gear: Usage

```bash title="Quickstart commands"
# Bootstrap a new machine from a remote dotfiles repository
enstow init https://github.com/username/dotfiles.git

# Preview symlink and secret decryption actions without modifying disk
enstow apply --dry-run

# Apply specific dotfile packages
enstow apply zsh nvim git

# Ingest an existing secret file into a package encrypted with age
enstow add ~/.secrets/api.env -p secrets --encrypt

# Inspect sync, conflict, and secret drift status
enstow status

# Audit secret hygiene, permissions, and symlink health
enstow doctor

# Check for or install the latest GitHub release
enstow self-update --check
```

## :star: Contributing

See [Contributing](./CONTRIBUTING.md).

## :sparkles: Code of Conduct

See [Code of Conduct](./CODE_OF_CONDUCT.md).

## :scales: License

[Apache License 2.0][1]

## :pencil: Author

This project was started in 2026 by [Nicholas Wilde].

[Nicholas Wilde]: https://github.com/nicholaswilde/
[1]: https://github.com/nicholaswilde/enstow/blob/main/LICENSE
