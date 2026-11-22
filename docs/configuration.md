# Configuration

`enstow` supports optional configuration files in **TOML**, **YAML**, or **JSON** format. A fully commented template documenting all supported options and defaults is provided in [`assets/config.example.toml`](https://github.com/nicholaswilde/enstow/blob/main/assets/config.example.toml) (bundled in release packages as `config.example.toml`).

To quickly initialize configuration from the template:

```bash
mkdir -p ~/.config/enstow
cp config.example.toml ~/.config/enstow/config.toml
```

## :1234: Hierarchical Precedence

Settings resolve in strict hierarchical precedence order (highest to lowest):

1. **Command Line Arguments** (e.g. `--source`, `--target`, `--dry-run`, `--force`, `--backup`, `--backup-dir`, `--prune`, `--adopt`, `--age-key-file`, `--recipient`, `--profile`, `--editor`, `--ignore`, `--json`, `--mask-secrets`, `--no-hooks`, `--shred`, `--log-level`)
2. **Environment Variables** (e.g. `ENSTOW_SOURCE`, `ENSTOW_TARGET`, `ENSTOW_DRY_RUN`, `ENSTOW_FORCE`, `ENSTOW_BACKUP`, `ENSTOW_BACKUP_DIR`, `ENSTOW_PRUNE`, `ENSTOW_ADOPT`, `ENSTOW_AGE_KEY_FILE`, `ENSTOW_RECIPIENTS`, `ENSTOW_PACKAGES`, `ENSTOW_PROFILE`, `ENSTOW_IGNORE`, `ENSTOW_EDITOR`, `ENSTOW_JSON`, `ENSTOW_MASK_SECRETS`, `ENSTOW_NO_HOOKS`, `ENSTOW_SHRED`, `ENSTOW_LOG_LEVEL`)
3. **Configuration File** (discovered in order: `-C <path>` / `--config <path>` > `ENSTOW_CONFIG` > repo-local `.enstow.{toml,yaml,yml,json}` or `enstow.{toml,yaml,yml,json}` in `--source`, `ENSTOW_SOURCE`, or current directory > global `$XDG_CONFIG_HOME/enstow/config.{toml,yaml,yml,json}` / `~/.config/enstow/config.{toml,yaml,yml,json}`)
4. **Built-in Defaults** (`source = "."`, `target = "$HOME"`, `dry_run = false`, `force = false`, `backup = false`, `backup_dir = "$target/.enstow-backup"`, `prune = false`, `adopt = false`, `json = false`, `mask_secrets = false`, `no_hooks = false`, `shred = false`, `log_level = "info"`)

!!! note
    Relative `source` values in a configuration file (such as `source = "."` or `source = "packages"`) resolve relative to the configuration file's parent directory rather than the current working directory. `~`-prefixed and absolute paths are preserved as-is, and CLI `--source` or `ENSTOW_SOURCE` overrides take precedence.

    Ignore patterns from CLI arguments, `ENSTOW_IGNORE`, and configuration files merge additively without duplicates.

## :gear: Example Configuration Files

=== "TOML"

    ```toml title="~/.config/enstow/config.toml"
    source = "~/dotfiles"
    target = "~"
    dry_run = false
    force = false
    backup = false
    backup_dir = "~/.enstow-backup"
    prune = true
    adopt = false
    age_key_file = "~/.config/sops/age/keys.txt"
    recipients = [
      "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
    ]
    packages = ["zsh", "nvim", "git"]
    default_profile = "work"
    editor = "nvim"
    ignore = ["*.tmp", ".DS_Store", "*.swp"]
    json = false
    mask_secrets = false
    no_hooks = false
    shred = false
    log_level = "info"

    [profiles.work]
    packages = ["common", "git", "zsh", "work"]

    [profiles.server]
    packages = ["common", "bash", "server"]

    [permissions]
    "**/*.sh" = "0755"
    "**/*.key" = "0400"

    [package.ssh.permissions]
    "id_ed25519" = "0600"

    [hooks]
    pre_apply = "echo 'Starting deployment'"
    post_apply = "echo 'Deployment complete'"
    pre_unstow = "echo 'Starting unstow'"
    post_unstow = "echo 'Unstow finished'"

    [package.bat.hooks]
    post_apply = "bat cache --build"

    [package.macos-defaults]
    os = "macos"

    [package.linux-desktop]
    os = ["linux", "freebsd"]
    arch = "x86_64"
    hostname = ["workstation", "laptop"]
    ```

=== "YAML"

    ```yaml title="~/.config/enstow/config.yaml"
    source: ~/dotfiles
    target: ~
    dry_run: false
    force: false
    backup: false
    backup_dir: ~/.enstow-backup
    prune: true
    adopt: false
    age_key_file: ~/.config/sops/age/keys.txt
    recipients:
      - age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
    packages:
      - zsh
      - nvim
      - git
    default_profile: work
    profiles:
      work:
        packages:
          - common
          - git
          - zsh
          - work
      server:
        packages:
          - common
          - bash
          - server
    editor: nvim
    ignore:
      - "*.tmp"
      - ".DS_Store"
      - "*.swp"
    json: false
    mask_secrets: false
    no_hooks: false
    shred: false
    log_level: info
    permissions:
      "**/*.sh": "0755"
      "**/*.key": "0400"
    hooks:
      pre_apply: "echo 'Starting deployment'"
      post_apply: "echo 'Deployment complete'"
      pre_unstow: "echo 'Starting unstow'"
      post_unstow: "echo 'Unstow finished'"
    package:
      ssh:
        permissions:
          id_ed25519: "0600"
      bat:
        hooks:
          post_apply: "bat cache --build"
      macos-defaults:
        os: macos
      linux-desktop:
        os:
          - linux
          - freebsd
        arch: x86_64
        hostname:
          - workstation
          - laptop
    ```

=== "JSON"

    ```json title="~/.config/enstow/config.json"
    {
      "source": "~/dotfiles",
      "target": "~",
      "dry_run": false,
      "force": false,
      "backup": false,
      "backup_dir": "~/.enstow-backup",
      "prune": true,
      "adopt": false,
      "age_key_file": "~/.config/sops/age/keys.txt",
      "recipients": [
        "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
      ],
      "packages": [
        "zsh",
        "nvim",
        "git"
      ],
      "default_profile": "work",
      "profiles": {
        "work": {
          "packages": ["common", "git", "zsh", "work"]
        },
        "server": {
          "packages": ["common", "bash", "server"]
        }
      },
      "editor": "nvim",
      "ignore": [
        "*.tmp",
        ".DS_Store",
        "*.swp"
      ],
      "json": false,
      "mask_secrets": false,
      "no_hooks": false,
      "shred": false,
      "log_level": "info",
      "permissions": {
        "**/*.sh": "0755",
        "**/*.key": "0400"
      },
      "hooks": {
        "pre_apply": "echo 'Starting deployment'",
        "post_apply": "echo 'Deployment complete'",
        "pre_unstow": "echo 'Starting unstow'",
        "post_unstow": "echo 'Unstow finished'"
      },
      "package": {
        "ssh": {
          "permissions": {
            "id_ed25519": "0600"
          }
        },
        "bat": {
          "hooks": {
            "post_apply": "bat cache --build"
          }
        },
        "macos-defaults": {
          "os": "macos"
        },
        "linux-desktop": {
          "os": ["linux", "freebsd"],
          "arch": "x86_64",
          "hostname": ["workstation", "laptop"]
        }
      }
    }
    ```

## :no_entry_sign: Ignore Rules

Ignore specific files or patterns during dotfile operations using Git-style ignore syntax:

1. **Package Ignore File:** Create `.enstowignore` (or fallback `.stow-local-ignore`) inside a package root or source root.
2. **CLI Flags:** Pass `-i` / `--ignore` multiple times.
3. **Environment Variable:** Set `ENSTOW_IGNORE` (comma or colon separated).
4. **Configuration File:** Specify `ignore = ["*.tmp", ".DS_Store"]`.

### Git-Style Ignore Syntax

!!! note
    `enstow` does not support GNU Stow Perl regular expression syntax. All ignore files (including `.stow-local-ignore`) and pattern arguments are evaluated strictly using Git-style ignore rules.

`enstow` uses standard `.gitignore` semantics exclusively:

- **Wildcards:** `*.bak`, `temp_*.log` match across directories.
- **Recursive Directory Matching:** `**/logs/*.log` matches nested paths.
- **Directory Exclusions:** Trailing slash `build/` ignores entire directories and skips traversal.
- **Root Anchoring:** Leading slash `/only_at_root.txt` matches only at the package root.
- **Negation / Whitelisting:** Prefix `!` re-includes previously ignored files (e.g. `!keep.bak`).
- **Character Classes:** `cache[0-9].tmp`.
- **Comments & Blanks:** Lines beginning with `#` and empty lines are ignored.

```gitignore title=".enstowignore"
# Ignore editor and temporary artifacts
*.swp
*.bak
*~

# Ignore build directory
build/

# Ignore nested log files but keep one specific log
**/logs/*.log
!**/logs/keep.log

# Ignore a file only at package root
/install.sh
```

```bash
# Ignore patterns via CLI flags
enstow apply -i "*.bak" -i "*.tmp"

# Ignore patterns via environment variable
export ENSTOW_IGNORE="*.bak,*.tmp:*.swp"
enstow apply
```

## :hook: Lifecycle Hooks

Automate follow-up actions like rebuilding tool caches, reloading user units, or notifying daemons before or after `apply` and `unstow`:

```toml title="~/.config/enstow/config.toml"
[hooks]
pre_apply = "echo 'Starting deployment'"
post_apply = "echo 'Deployment complete'"
pre_unstow = "echo 'Starting unstow'"
post_unstow = "echo 'Unstow finished'"

[package.bat.hooks]
post_apply = "bat cache --build"
```

Contextual environment variables are passed to each hook:

- `ENSTOW_PACKAGE`: Name of the package being deployed (empty for global hooks).
- `ENSTOW_SOURCE`: Path to dotfile package source directory.
- `ENSTOW_TARGET`: Target deployment root directory.
- `ENSTOW_HOOK_TYPE`: Type of hook (`pre_apply`, `post_apply`, `pre_unstow`, `post_unstow`).
- `ENSTOW_DRY_RUN`: `true` or `false`.
- `ENSTOW_FORCE`: `true` or `false`.

Hooks can be bypassed on demand:

```bash
# Bypass lifecycle hook execution (alias: --skip-hooks)
enstow apply --no-hooks
```

## :card_index_dividers: Package Profiles

Group packages into named profiles for different machines or roles:

```toml title="~/.config/enstow/config.toml"
default_profile = "work"

[profiles.work]
packages = ["common", "git", "zsh", "work"]

[profiles.server]
packages = ["common", "bash", "server"]
```

Select a profile via CLI or environment variable:

```bash
enstow apply --profile server
# Or:
ENSTOW_PROFILE=work enstow apply
```

## :computer: Platform & Host Condition Filters

Target multiple operating systems, CPU architectures, and hostnames in a single configuration without duplicating profiles:

```toml title="~/.config/enstow/config.toml"
[package.macos-defaults]
os = "macos"

[package.linux-desktop]
os = ["linux", "freebsd"]
arch = "x86_64"
hostname = ["workstation", "laptop"]
```

Non-matching packages are automatically skipped during `apply`, `restow`, `unstow`, and `status`.

## :lock: Custom Target Permissions

Decrypted secrets and rendered `.tmpl` files default to mode `0600` (`-rw-------`) on Unix. Override permissions globally by glob pattern or per package:

```toml title="~/.config/enstow/config.toml"
[permissions]
"**/*.sh" = "0755"
"**/*.key" = "0400"

[package.ssh.permissions]
"id_ed25519" = "0600"
```

## :earth_americas: Environment Variables Reference

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
| `ENSTOW_ADOPT` | `adopt` | `--adopt` | Adopt conflicting destination files into source package during apply (`true`/`false`) | `false` |
| `ENSTOW_NO_HOOKS` | `no_hooks` | `--no-hooks` | Skip execution of pre- and post-lifecycle hooks (`true`/`false`) | `false` |
| `ENSTOW_SHRED` | `shred` | `--shred` | Securely zeroize decrypted secrets before unlinking (`true`/`false`) | `false` |
| `ENSTOW_AGE_KEY_FILE` / `SOPS_AGE_KEY_FILE` | `age_key_file` | `--age-key-file` | Path to age identity key file for encryption/decryption | None |
| `ENSTOW_SSH_KEY_FILE` | N/A | `--age-key-file` | Path to SSH private key identity file for decryption / recipient derivation | `~/.ssh/id_ed25519`, `~/.ssh/id_rsa` |
| `ENSTOW_SSH_PASSPHRASE` / `SSH_PASSPHRASE` | N/A | N/A | Passphrase for encrypted SSH private key identities | None (prompts interactively) |
| `ENSTOW_RECIPIENTS` / `SOPS_AGE_RECIPIENTS` | `recipients` | `-r`, `--recipient` | Age or SSH recipient public keys for encryption | None |
| `ENSTOW_PACKAGES` | `packages` | `PACKAGES` | Default packages to stow when none specified | None |
| `ENSTOW_PROFILE` | `default_profile` / `profiles` | `--profile` | Profile to select packages from configuration | None |
| `ENSTOW_IGNORE` | `ignore` | `-i`, `--ignore` | Additional glob patterns to ignore (comma or colon separated) | None |
| `ENSTOW_EDITOR` / `VISUAL` / `EDITOR` | `editor` | `--editor` | Editor command for interactive secret editing (`enstow edit`) | `nano` |
| `ENSTOW_JSON` | `json` | `--json` | Emit `status`, `diff`, and `doctor` output in JSON format (`true`/`false`) | `false` |
| `ENSTOW_MASK_SECRETS` | `mask_secrets` | `--mask-secrets` | Mask sensitive secret contents in `enstow diff` output (`true`/`false`) | `false` |
| `ENSTOW_LOG_LEVEL` | `log_level` | `--log-level` | Log filter level (`trace`, `debug`, `info`, `warn`, `error`, `off`) | `info` |
| `GH_TOKEN` / `GITHUB_TOKEN` | N/A | N/A | GitHub token for `enstow self-update` to bypass unauthenticated API rate limits (60/hr -> 5,000/hr; `GH_TOKEN` takes precedence) | None |
