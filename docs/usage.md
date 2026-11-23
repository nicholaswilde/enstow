# Usage

```bash
enstow [OPTIONS] [COMMAND]
```

When executed without a subcommand (`enstow`), it runs the default `apply` command with common options. Repo-local `.enstow.{toml,yaml,yml,json}` (or `enstow.*`) files in `--source`, `ENSTOW_SOURCE`, or the current working directory are discovered automatically without passing `-C`.

## :keyboard: Command Reference

| Command | Alias | Description | Example |
| :--- | :--- | :--- | :--- |
| `init` | — | Bootstrap dotfile repository onboarding: clone, detect host/profile, check keys, and apply | `enstow init [REPO] [-s ~/.dotfiles]` |
| `add` | — | Ingest an existing machine dotfile into a package as a symlink or encrypted secret | `enstow add <file> -p <pkg> [--encrypt]` |
| `apply` | `sync` | Symlink regular files and decrypt secret files to target destination | `enstow apply [PACKAGES...]` |
| `restow` | — | Clean stale symlinks/secrets and re-apply packages in one step | `enstow restow [PACKAGES...]` |
| `unstow` | — | Remove symlinks and decrypted secret files managed by `enstow` | `enstow unstow [PACKAGES...] [--shred]` |
| `scrub` | — | Securely shred and remove decrypted secrets and symlinks | `enstow scrub [PACKAGES...]` |
| `status` | — | Inspect sync, missing, conflict, modified (drift), and unverified state | `enstow status [--changes-only] [--check] [--json]` |
| `diff` | — | Show unified diff between dotfiles and target destination | `enstow diff [--mask-secrets] [--json]` |
| `doctor` | `lint` | Audit system health, secret hygiene, permissions, symlinks, and git staged/tracked files | `enstow doctor [--staged \| --tracked] [--json]` |
| `keygen` | — | Generate an X25519 `age` identity key file with `0600` permissions and print its public key | `enstow keygen [-o <path>] [--force]` |
| `encrypt` | — | Encrypt a secret dotfile into `.age` format | `enstow encrypt <file> [-r <key>]` |
| `decrypt` | — | Decrypt an `age` or `sops` encrypted secret file to stdout or file | `enstow decrypt <file> [-o <out>]` |
| `edit` | — | Interactively decrypt, edit in `$EDITOR`, re-encrypt, and optionally `--apply` an `age` secret file | `enstow edit <file.age> [--apply]` |
| `rekey` | — | Re-encrypt `.age` secrets across packages with updated recipients | `enstow rekey -r <key> [PACKAGES...]` |
| `completions` | — | Output dynamic or static shell completion script (`bash`, `zsh`, `fish`, `powershell`, `elvish`) | `enstow completions zsh [--static]` |
| `man` | — | Output UNIX roff man page | `enstow man > assets/enstow.1` |
| `self-update` | `update` | Update `enstow` to the latest or specified GitHub release | `enstow self-update [--check] [--yes]` |

For key generation, secret encryption, decryption, editing, rekeying, SSH keys, `.tmpl` templates, and scrubbing details, see [Secrets & Templates](./secrets.md).

## :rocket: Bootstrapping a New Machine (`enstow init`)

Bootstrap dotfile management on a new machine in a single command:

```bash
# Clone remote dotfiles to ~/.dotfiles, auto-detect host/profile, check/import age key, run pre-flight check, and apply
enstow init https://github.com/username/dotfiles.git

# Preview onboarding actions without modifying disk
enstow init https://github.com/username/dotfiles.git --dry-run

# Clone a specific branch into a custom source directory
enstow init https://github.com/username/dotfiles.git --branch main -s ~/dotfiles
```

## :link: Applying Dotfiles (`enstow apply`)

Apply all packages or specific packages to the target directory (default: `$HOME`):

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

# Backup conflicting target files to ~/.enstow-backup/<YYYYMMDD_HHMMSS> before overwriting
enstow apply --backup zsh
enstow apply -b --backup-dir ~/.dotfiles-backup/{timestamp} zsh

# Prune stale symlinks no longer present in source packages
enstow apply --prune zsh
```

## :inbox_tray: Ingesting Dotfiles (`enstow add`)

Onboard existing machine dotfiles into a package, preserving their relative directory hierarchy:

```bash
# Ingest an existing config into a package and replace it with a symlink
enstow add ~/.config/app/config.json -p app

# Ingest and encrypt into an .age secret file, deploying decrypted secret with 0600 mode
enstow add ~/.secrets/api.env -p secrets --encrypt

# Preview actions without filesystem mutations
enstow add ~/.bashrc -p shell --dry-run

# Overwrite existing package file if it conflicts
enstow add ~/.config/nvim/init.lua -p nvim --force
```

## :arrows_counterclockwise: Restowing Packages (`enstow restow`)

Clean stale/orphaned symlinks and re-apply packages in one step:

```bash
# Preview restow
enstow restow --dry-run zsh

# Restow target packages
enstow restow zsh nvim
```

## :broom: Unstowing & Scrubbing Dotfiles (`enstow unstow` / `scrub`)

Remove symlinks and decrypted secret files managed by `enstow`:

```bash
# Preview removal
enstow unstow --dry-run zsh

# Unstow specific packages
enstow unstow zsh nvim

# Securely shred decrypted secret files with zeros before unlinking
enstow unstow --shred zsh nvim

# Dedicated scrub command (equivalent to unstow --shred)
enstow scrub zsh nvim
```

## :bar_chart: Inspecting Status (`enstow status`)

Check sync, missing, conflicting, modified (drifted), or unverified state for dotfiles:

```bash
# Human-readable status overview with summary counts
enstow status

# Hide SYNCED rows to surface missing, conflicting, or drifted entries (alias: --short)
enstow status --changes-only

# Status with explicit age key for secret drift verification
enstow status --age-key-file ~/.config/sops/age/keys.txt

# Status for specific packages
enstow status zsh nvim

# Machine-readable JSON output (can also be enabled via ENSTOW_JSON=1 or json = true in config)
enstow status --json

# Exit with code 1 if any dotfile or secret is not SYNCED (alias: --exit-code)
enstow status --check
```

States reported:

- `SYNCED`: Symlink points to valid source, or target plaintext matches decrypted secret.
- `MISSING`: Source dotfile exists, but target file does not yet exist.
- `CONFLICT`: Target file exists as unmanaged file, incorrect symlink, or directory.
- `MODIFIED`: Target secret file exists, but content has drifted from the decrypted source.
- `UNVERIFIED`: Target secret file exists, but decryption keys are missing or unavailable.

In text mode, `enstow status` prints a summary footer (`Status summary: N synced, N missing, N conflict, N modified, N unverified.`). Passing `--changes-only` (alias `--short`) hides `SYNCED` entries in both text and `--json` output while preserving the full status counts in the text summary footer and keeping `--json` strictly valid JSON.

## :mag: Inspecting Diffs (`enstow diff`)

Show unified diffs between package dotfiles (including in-memory decrypted secrets) and target destinations:

```bash
# Show unified diffs across all managed packages
enstow diff

# Mask sensitive contents when diffing secret files (alias: --no-secrets)
enstow diff --mask-secrets

# Output diffs for specific packages in JSON format
enstow diff --json zsh nvim
```

## :stethoscope: System Diagnostics (`enstow doctor`)

Audit repository and deployment health (also aliased as `enstow lint`):

```bash
# Run full diagnostics
enstow doctor

# Inspect git staged files for plaintext secrets, .env/key files, and leaks (pre-commit hook)
enstow doctor --staged

# Audit all git-tracked files across the repository for forbidden secret files and leaks (CI)
enstow doctor --tracked

# Machine-readable JSON diagnostics report
enstow doctor --json
```

Checks performed by `enstow doctor`:

- **Package Collisions:** Detects duplicate target paths claimed by multiple packages.
- **Symlink Health:** Identifies broken, dangling, stale, or legacy folded directory symlinks.
- **Secret Permissions:** Verifies decrypted secret targets enforce `0600` (or configured) permissions on Unix.
- **Decryption Prerequisites:** Checks availability of configured `age`/SSH identity keys and the `sops` binary when `.sops.*` files are present.
- **Secret Guard:** Flags plaintext siblings sitting alongside `.age`/`.sops.*` files in the repository (even if `.enstowignore`d) and warns if plaintext counterparts are missing from `.gitignore`. With `--staged`, inspects `git diff --cached` for pre-commit checks; with `--tracked` (mutually exclusive with `--staged`), audits all git-tracked files (`git ls-files`) for forbidden `.env`/private key filenames (`*.key`, `*.pem`, `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `id_ed25519_sk`, `id_ecdsa_sk`), plaintext counterparts, and credential leaks as errors (exiting non-zero on findings).
- **Secret Leak Scan:** Flags unencrypted sensitive files inside managed packages.

## :shield: Conflict Resolution & Backups

When a target destination already exists with different content or unmanaged files:

- **Dry-run (`-n`, `--dry-run`):** Previews what actions would occur without touching disk.
- **Interactive (`-I`, `--interactive`):** Prompts on each collision or secret drift with `[d]iff`, `[o]verwrite`, `[a]dopt`, or `[s]kip`.
- **Adopt (`--adopt`):** Copies conflicting target files into the source package (overwriting source) and re-links; conflicting decrypted secrets are re-encrypted back to `.age` using configured recipients.
- **Force (`-f`, `--force`):** Overwrites conflicting target files or replaces differing symlinks.
- **Backup (`-b`, `--backup`):** Relocates colliding destination files out of the way before creating the new link or secret. Only creates the backup directory lazily when at least one file is actually backed up (skipped on `--dry-run` or zero conflicts) and prints the backup path summary when files are moved.
- **Backup Directory (`--backup-dir <path>`):** Sets custom destination for backups. Defaults to `$TARGET/.enstow-backup/{timestamp}`, expanding `{timestamp}` to a `YYYYMMDD_HHMMSS` UTC subdirectory per run (with `_1`, `_2`, ... suffixes if multiple runs occur within the same second) so repeated `--backup` runs never overwrite earlier backups. Explicit `--backup-dir` paths also expand `{timestamp}` if present, or stay literal when omitted.

```bash
# Interactively resolve collisions and secret drift file-by-file
enstow apply -I zsh

# Safely apply with default timestamped backup ($TARGET/.enstow-backup/<YYYYMMDD_HHMMSS>)
enstow apply -b zsh

# Custom timestamped backup directory
enstow apply -b --backup-dir "$HOME/backup-dir/{timestamp}" zsh

# Explicit literal backup directory (no automatic timestamp subdirectory)
enstow apply -b --backup-dir ~/backup-dir zsh

# Adopt existing target files into source package and replace with symlinks
enstow apply --adopt zsh
```

## :scissors: Pruning Stale Symlinks

When removing or renaming files in your dotfiles repository, stale links may remain in your target directory. Pruning works with `enstow apply --prune`, the default no-subcommand `enstow --prune` (or `prune = true` in config), `enstow restow`, and `enstow unstow`. Stale-symlink scans are scoped to managed target subtrees with dynamic depth so deeply nested managed files (6+ levels deep) are pruned without walking unrelated directories across `$HOME`:

```bash
# Automatically remove broken or orphaned symlinks for managed packages during apply
enstow apply --prune zsh

# Equivalent using default no-subcommand apply
enstow --prune zsh

# Preview pruning actions
enstow apply --prune --dry-run zsh
```
