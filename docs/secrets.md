# Secrets & Templates

`enstow` natively manages encrypted secret dotfiles (`.age`, `.sops.yaml`, `.sops.*`) and secret-substituted templates (`.tmpl`). Secrets are decrypted or rendered strictly in memory and written directly to their target paths with restricted permissions (`0600` on Unix) so plaintext credentials never enter version control.

!!! important
    Never commit plaintext secret files into your dotfiles repository. Use `enstow encrypt` or `enstow add --encrypt`, and run `enstow doctor` to catch accidental plaintext leaks or loose permissions.

## :file_folder: Detection Patterns & Target Mapping

`enstow` automatically recognizes encrypted files and templates by extension and maps them to plaintext target filenames during `apply`, `restow`, `status`, `diff`, and `unstow`:

| Source File Pattern | Engine | Deployed Target Filename | Default Permissions |
| :--- | :--- | :--- | :--- |
| `<name>.age` | `age` (built-in) | `<name>` | `0600` (`-rw-------`) |
| `<name>.sops.yaml` | `sops` CLI | `<name>.yaml` | `0600` (`-rw-------`) |
| `<name>.sops.json` | `sops` CLI | `<name>.json` | `0600` (`-rw-------`) |
| `<name>.sops.<ext>` | `sops` CLI | `<name>.<ext>` | `0600` (`-rw-------`) |
| `.sops.yaml` (exact) | `sops` CLI | `.sops.yaml` | `0600` (`-rw-------`) |
| `<name>.tmpl` | Template renderer | `<name>` | `0600` (`-rw-------`) |

## :key: Generating an Age Identity Key (`enstow keygen`)

Generate an X25519 `age` identity key file in standard `age-keygen` format (`# created:`, `# public key:`, `AGE-SECRET-KEY-...`) with strict `0600` permissions, without needing the external `age` CLI:

```bash
# Generate key at the default location (~/.config/sops/age/keys.txt or $XDG_CONFIG_HOME/sops/age/keys.txt)
enstow keygen

# Write the key to a custom path
enstow keygen -o ~/keys/work.txt

# Overwrite an existing key file (refused by default without --force)
enstow keygen --force
```

`enstow keygen` prints the generated public recipient (`age1...`) so you can paste it directly into `recipients = ["age1..."]` in `.enstow.toml`.

## :lock: Encrypting Secrets (`enstow encrypt`)

Encrypt a plaintext dotfile into an `.age` encrypted file:

```bash
# Encrypt using explicit recipient public key
enstow encrypt config.env -r age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

# Encrypt using identity file to derive recipient
enstow encrypt secret.json --age-key-file ~/.config/sops/age/keys.txt

# Specify custom output path (defaults to <file>.age)
enstow encrypt secret.json -o secret.json.age -r age1ql3z...

# Encrypt with a passphrase instead of recipient public keys
enstow encrypt secret.json --passphrase
```

When encrypting or re-encrypting (`encrypt`, `edit`, `rekey`), recipients resolve in order:

1. Explicit `-r` / `--recipient` CLI flags.
2. Derived from `--age-key-file`, `ENSTOW_AGE_KEY_FILE`, or `SOPS_AGE_KEY_FILE`.
3. Configured `recipients = [...]` in config file or `ENSTOW_RECIPIENTS` / `SOPS_AGE_RECIPIENTS`.

## :unlock: Decrypting Secrets (`enstow decrypt`)

Decrypt an `.age` or `.sops.*` secret file to stdout or a target path:

```bash
# Decrypt an age or sops secret file to stdout
enstow decrypt secret.env.age

# Decrypt to a specific output file
enstow decrypt secret.env.age -o secret.env

# Decrypt using an explicit identity key file
enstow decrypt secret.env.age --age-key-file ~/.config/sops/age/keys.txt
```

## :pencil2: Editing Secrets (`enstow edit`)

Interactively decrypt, edit in `$ENSTOW_EDITOR` (or `$VISUAL` / `$EDITOR`), and re-encrypt an `.age` file in memory:

```bash
# Edit using default editor ($ENSTOW_EDITOR / $VISUAL / $EDITOR / system fallback)
enstow edit secret.env.age

# Edit and immediately re-deploy updated plaintext target (0600 or configured mode)
enstow edit --apply bash/.tokens.age

# Edit using explicit key file
enstow edit secret.env.age --age-key-file ~/.config/sops/age/keys.txt

# Edit using specific editor command
enstow edit secret.env.age --editor "nano"
```

## :key: Rekeying Secrets (`enstow rekey`)

Rotate keys across packages by re-encrypting all discovered `.age` secret files to updated recipients:

```bash
# Preview which .age secrets would be re-encrypted
enstow rekey --dry-run -r age1ql3z...

# Re-encrypt all .age secrets across packages to new recipients
enstow rekey -r age1ql3z... -r ~/.ssh/id_ed25519.pub

# Rekey specific packages using an explicit identity file
enstow rekey --age-key-file ~/.config/sops/age/keys.txt zsh nvim
```

## :closed_lock_with_key: SSH Key Encryption & Decryption

`enstow` natively supports SSH public and private keys (`ssh-ed25519` and `ssh-rsa`) for secret encryption and decryption without generating a separate `age` keypair.

### Encrypting with SSH Keys

```bash
# Encrypt using raw SSH public key string
enstow encrypt secret.env -r "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."
enstow encrypt secret.env -r "ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB..."

# Encrypt using an SSH public key file
enstow encrypt secret.env -r ~/.ssh/id_ed25519.pub

# Derive recipient public key directly from SSH private key
enstow encrypt secret.env --age-key-file ~/.ssh/id_ed25519

# Ingest dotfile into a package and encrypt to SSH key
enstow add ~/.secrets/api.env -p secrets --encrypt -r ~/.ssh/id_ed25519.pub
```

### Decrypting with SSH Keys

During `apply`, `status`, `diff`, `decrypt`, `edit`, or `rekey`, secret files are decrypted in memory using:

- **Automatic SSH Key Discovery:** When `--age-key-file` is omitted, `enstow` automatically checks:
  1. `~/.config/sops/age/keys.txt`
  2. `~/.ssh/id_ed25519`
  3. `~/.ssh/id_rsa`

- **Explicit Identity File:**

    ```bash
    enstow apply --age-key-file ~/.ssh/id_ed25519
    ```

- **Passphrase-Protected Keys:**
  If an SSH private key is encrypted with a passphrase, `enstow` prompts interactively via terminal, or reads non-interactively from `ENSTOW_SSH_PASSPHRASE` or `SSH_PASSPHRASE`.

## :page_facing_up: Template Rendering & Secret Substitution (`.tmpl`)

Files ending in `.tmpl` (e.g. `.gitconfig.tmpl` -> `.gitconfig`) are rendered in memory and written to the target directory with `0600` (or custom configured) permissions:

```ini title="git/.gitconfig.tmpl"
[user]
    name = {{ env.GIT_AUTHOR_NAME }}
    signingkey = {{ secrets.GPG_KEY }}
[github]
    token = {{ secrets.github.token }}
[host]
    os = {{ os }}
    arch = {{ arch }}
    hostname = {{ hostname }}
    profile = {{ profile }}
```

- **Contextual Variables:** `{{ os }}`, `{{ arch }}`, `{{ hostname }}`, `{{ profile }}`, and `{{ env.VAR }}`.
- **Encrypted Key-Value Secret Stores:** Reference `{{ secrets.KEY }}` or `{{ secrets.<store>.KEY }}` from `.age` / `.sops.*` files (`.env`, `.toml`, `.yaml`, `.json`) in the package or repository root. Hidden secret stores named `.secrets.age` or `.secrets.*.age` are automatically excluded from direct file deployment.

## :fire: Secure Secret Scrubbing & Permission Hygiene

- **Strict Default Permissions (`0600`):** Every generated `age` identity key (`enstow keygen`), decrypted secret, and rendered `.tmpl` target is created with mode `0600` (`-rw-------`) on Unix. Re-running `enstow apply` skips already-synced secrets idempotently while healing loose permissions. Customize target modes per glob or per package via `[permissions]` and `[package.<name>.permissions]` in [Configuration](./configuration.md#custom-target-permissions).

- **Zeroize-Before-Unlink (`--shred` / `scrub`):** When decommissioning a machine or removing sensitive dotfiles, overwrite decrypted target files with zeros and flush to disk before unlinking:

    ```bash
    # Dedicated scrub command (equivalent to unstow --shred)
    enstow scrub zsh secrets

    # Or pass --shred directly to unstow
    enstow unstow --shred zsh secrets
    ```

- **Continuous Verification:** Run [`enstow doctor`](./usage.md#system-diagnostics-enstow-doctor) to verify that all deployed secret files retain `0600` permissions, that no plaintext siblings sit alongside `.age`/`.sops.*` files in the repository, and that plaintext counterparts are covered by `.gitignore`.

- **Git Pre-Commit Secret Guard (`doctor --staged`):** Install a zero-maintenance `.git/hooks/pre-commit` hook that blocks staged plaintext counterparts of encrypted files, unencrypted `.env` or private key files (`*.key`, `*.pem`, `id_rsa`, `id_ed25519`), and credential patterns:

    ```bash
    cat << 'EOF' > .git/hooks/pre-commit
    #!/usr/bin/env sh
    exec enstow doctor --staged
    EOF
    chmod +x .git/hooks/pre-commit
    ```

- **CI Repo-Wide Secret Guard (`doctor --tracked`):** Audit every git-tracked file (`git ls-files`) across the repository — including root files and `.enstowignore`d paths — for forbidden `.env`/private key filenames, unencrypted counterparts of `.age`/`.sops.*` files, and credential leaks, exiting non-zero on findings:

    ```bash
    # Run in CI workflows (human-readable or JSON output)
    enstow doctor --tracked
    enstow doctor --tracked --json
    ```
