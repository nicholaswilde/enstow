# Project Specification: enstow

## Overview

`enstow` is a Rust-based command-line tool that acts as a secret-aware dotfile manager. It combines the symlinking capabilities of GNU `stow` with the seamless decryption capabilities of `sops` and `age`.

When `enstow` runs, it scans a dotfiles directory. If it finds standard files, it symlinks them to the target directory. If it finds encrypted files (e.g., `.sops.yaml` or `.age`), it securely decrypts them in memory and injects the plaintext into the target destination with strict file permissions (`600`), ensuring secrets are never checked into public version control.

## Project Setup Instructions for `agy`

Please initialize a new Rust binary project named `enstow` with the following requirements. Use the architecture and standards from the `tfa` repository as a baseline for CI/CD, Taskfile execution, and agent rules.

### 1. Dependencies (`Cargo.toml`)

Include the following core crates:

- `clap` (with `derive` feature) for CLI argument parsing.
- `anyhow` for top-level error handling.
- `thiserror` for library-level typed errors.
- `tracing` and `tracing-subscriber` for logging/telemetry.
- `walkdir` for recursively traversing dotfile directories.
- `serde` and `serde_json`/`serde_yaml` for parsing configurations.
- `age` and `sops` (or generic command execution for now) for handling decryption.

### 2. Directory Structure & Files

Generate the boilerplate for the following structure:

**Root Files:**

- `Cargo.toml`: Configured with the dependencies above.
- `Taskfile.yml`: Include standard tasks for `build`, `test`, `lint`, and `run` (similar to `tfa`).
- `README.md`: Basic description of `enstow` and its usage.
- `.gitignore`: Standard Rust gitignore.

**GitHub Actions (`.github/workflows/`):**

- `ci.yml`: Standard cargo test, clippy, and rustfmt checks.
- `release.yml`: Release automation for building binaries.

**Agent Rules (`.agents/rules/`):**

- Copy standard rules from `tfa` (e.g., `rust-rules.md`, `no-secrets.md`) to guide future LLM interactions.

**Source Code (`src/`):**

- `main.rs`: Setup tracing, parse CLI arguments, and handle top-level results.
- `cli.rs`: Define the `clap` structs and commands (e.g., `enstow apply`, `enstow encrypt`, `enstow status`).
- `stow.rs`: Logic for determining symlink paths and creating symlinks.
- `crypto.rs`: Stubs and logic for integrating with `age`/`sops` decryption.
- `error.rs`: Custom error definitions using `thiserror`.

### 3. Initial CLI Definition

In `src/cli.rs`, define a basic `clap` Parser with the following skeleton:

- `source`: The directory containing the dotfiles (default: current directory).
- `target`: The target directory to apply the dotfiles (default: `$HOME`).
- `dry-run`: A flag to preview what symlinks and decryptions will happen without actually writing to disk.

### 4. Implementation Steps

1. Create the base project structure and config files.
2. Setup the CLI parsing logic.
3. Implement a simple file walker in `stow.rs` that prints out the intended source and target paths for a dry-run.
