# About

`enstow` is a high-performance, single-binary Rust CLI secret-aware dotfile manager that combines modular GNU [`stow`][1] symlinking with seamless [`sops`][2] and [`age`][3] decryption. It lets you keep both ordinary configuration files and encrypted credentials in a single dotfiles repository without ever committing plaintext secrets.

## :sparkles: Features

- **Symlink Management:** Scans modular dotfile packages (e.g. `zsh`, `nvim`, `git`) and cleanly symlinks non-secret files into your target destination (default: `$HOME`).
- **Dotfile Ingestion & Adoption:** Ingest existing machine dotfiles into packages with `enstow add` (with optional `--encrypt`), or adopt conflicting host files during deployment via `enstow apply --adopt`.
- **Secret Decryption & SSH Keys:** Recognizes encrypted files (`.age`, `.sops.yaml`, `.sops.json`, `.sops.<ext>`), decrypts them in memory using native `age` keys or SSH keys (`ssh-ed25519`, `ssh-rsa`), and deploys plaintext targets with strict `0600` permissions.
- **Template Rendering (`.tmpl`):** Renders templates in memory with host/environment context (`os`, `arch`, `hostname`, `profile`, `env.VAR`) and encrypted secret-store substitution (`secrets.KEY`).
- **Machine Bootstrapping:** Clone a remote dotfiles repository, detect host/profile filters, check or import decryption keys, and deploy in one step with `enstow init`.
- **Unstow, Restow & Scrub:** Cleanly unlink managed dotfiles, restow packages while pruning stale symlinks, or zeroize and remove decrypted secret files via `enstow scrub` / `unstow --shred`.
- **Collision, Backup & Interactive Resolution:** Preview actions (`--dry-run`), resolve collisions interactively (`--interactive`), relocate conflicts (`--backup`, `--backup-dir`), adopt host files (`--adopt`), or overwrite (`--force`).
- **Status, Diff & Health Diagnostics:** Inspect sync and secret drift states (`enstow status`), view unified diffs with optional secret masking (`enstow diff --mask-secrets`), and audit secret hygiene, permissions, and symlink health (`enstow doctor`).
- **Secret Lifecycle Management:** Encrypt (`enstow encrypt`), decrypt (`enstow decrypt`), interactively edit in `$EDITOR` (`enstow edit`), and rotate recipients across packages (`enstow rekey`).
- **Lifecycle Hooks & Condition Filters:** Run global or per-package `pre_apply`, `post_apply`, `pre_unstow`, and `post_unstow` hooks, select package profiles, and filter packages by `os`, `arch`, and `hostname`.
- **Git-Style Ignore Rules:** Filter files using `.enstowignore`, `.stow-local-ignore`, `--ignore` / `-i` CLI flags, `ENSTOW_IGNORE`, or configuration files.
- **Dynamic Shell Completions & Man Page:** Dynamic `<TAB>` completion across Bash, Zsh, Fish, PowerShell, and Elvish via `clap_complete`, plus UNIX roff man page generation (`enstow man`).
- **Lightweight & Portable:** Static, zero-fluff binary compiled for Linux (AMD64, ARM64, ARMv7, ARMv6), macOS, and Windows.

## :shield: Architecture & Security Guarantees

- **Symlinks for Plaintext, Copies for Secrets:** Regular configuration files are linked directly to the repository via filesystem symlinks. Secret files (`.age`, `.sops.*`) and rendered templates (`.tmpl`) are never symlinked; their contents are decrypted or rendered in memory and written directly to the destination path.
- **Zero Plaintext in Version Control:** Plaintext secrets never touch your dotfiles working tree. Decryption buffers stay in memory until written directly to the target path outside the repository.
- **Strict Permission Hygiene:** Decrypted secret targets default to mode `0600` (`-rw-------`) on Unix, with optional per-glob or per-package overrides in [Configuration](./configuration.md#custom-target-permissions).
- **Secure Scrubbing:** Removing decrypted targets with [`enstow scrub`](./secrets.md#secure-secret-scrubbing-permission-hygiene) or `enstow unstow --shred` overwrites file bytes with zeros and flushes to disk before unlinking.
- **Pre-Flight Auditing:** Run [`enstow doctor`](./usage.md#system-diagnostics-enstow-doctor) to detect package collisions, broken symlinks, overly permissive secret targets, missing decryption prerequisites, and accidental plaintext secret leaks.

[1]: https://www.gnu.org/software/stow/
[2]: https://getsops.io/
[3]: https://github.com/FiloSottile/age
