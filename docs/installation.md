# Installation

`enstow` is distributed as a prebuilt Rust binary via Homebrew, APT, Scoop, and GitHub Releases, or can be compiled from source with Cargo.

## :beer: Homebrew (macOS / Linux)

Install `enstow` via [Homebrew](https://brew.sh/) using the [`nicholaswilde/homebrew-tap`](https://github.com/nicholaswilde/homebrew-tap):

```bash
brew install nicholaswilde/homebrew-tap/enstow
```

Or tap the repository first:

```bash
brew tap nicholaswilde/homebrew-tap
brew install enstow
```

## :package: APT (Debian / Ubuntu)

Install `.deb` packages (`amd64`, `arm64`, `armhf`, `armel`) from the [`nicholaswilde/apt`](https://github.com/nicholaswilde/apt) repository ([nicholaswilde.io/apt](https://nicholaswilde.io/apt)), which bundles the binary, man page, and shell completions:

### 1. Add Repository Signing Key

```bash
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://nicholaswilde.io/apt/public.key | sudo gpg --dearmor -o /etc/apt/keyrings/nicholaswilde-apt.gpg
sudo chmod a+r /etc/apt/keyrings/nicholaswilde-apt.gpg
```

### 2. Add APT Source

=== "Deb822 (Debian 12+ / Ubuntu 22.04+)"

    ```bash
    sudo tee /etc/apt/sources.list.d/nicholaswilde.sources << 'EOF'
    Types: deb
    URIs: https://nicholaswilde.io/apt
    Suites: stable
    Components: main
    Signed-By: /etc/apt/keyrings/nicholaswilde-apt.gpg
    EOF
    ```

=== "Traditional One-Line (`.list`)"

    ```bash
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/nicholaswilde-apt.gpg] https://nicholaswilde.io/apt stable main" | sudo tee /etc/apt/sources.list.d/nicholaswilde-apt.list
    ```

### 3. Update & Install

```bash
sudo apt update
sudo apt install enstow
```

## :icecream: Scoop (Windows)

Install `enstow` on Windows via [Scoop](https://scoop.sh/) using [`nicholaswilde/scoop-bucket`](https://github.com/nicholaswilde/scoop-bucket):

```powershell
scoop bucket add nicholaswilde https://github.com/nicholaswilde/scoop-bucket
scoop install enstow
```

## :inbox_tray: GitHub Releases & Self-Update

Download prebuilt archives (`.tar.gz`, `.zip`) and `.deb` packages for Linux, macOS, and Windows from the [GitHub Releases](https://github.com/nicholaswilde/enstow/releases) page.

Update `enstow` in-place directly from `nicholaswilde/enstow` GitHub Releases (also aliased as `enstow update`):

```bash
# Check if a newer release is available without modifying the binary
enstow self-update --check

# Update interactively to the latest release
enstow self-update

# Download and install the latest release without prompting
enstow self-update --yes

# Install a specific release version
enstow self-update --version 0.1.15

# Pass a GitHub token to raise the API rate limit (60/hr -> 5,000/hr)
GH_TOKEN=ghp_... enstow self-update
```

!!! tip
    `enstow self-update` checks `GH_TOKEN`, then `GITHUB_TOKEN` (in order of precedence) to authenticate GitHub API requests and avoid unauthenticated IP rate limits.

## :crab: Build or Install from Source

### Prerequisites

- [Rust toolchain](https://rustup.rs/) (1.88+)
- [Task](https://taskfile.dev/) (optional, recommended)
- [`sops`](https://getsops.io/) (optional, required only when decrypting `.sops.*` files; `age` key generation, encryption, and decryption are built into `enstow`)

### Install or Build Locally

```bash title="Install with Cargo"
cargo install --git https://github.com/nicholaswilde/enstow
```

```bash title="Build locally"
git clone https://github.com/nicholaswilde/enstow.git
cd enstow
task build:local
# Or directly with Cargo:
cargo build --release
```

The compiled binary will be placed at `target/release/enstow`.

## :books: Shell Completions

`enstow` features dynamic autocompletion for commands, options, and packages. Shell scripts can be generated for Bash, Zsh, Fish, PowerShell, and Elvish:

=== "Bash"

    ```bash
    # Add to ~/.bashrc for interactive sessions:
    eval "$(enstow completions bash)"

    # Or install to standard completion directory:
    enstow completions bash > ~/.local/share/bash-completion/completions/enstow
    ```

=== "Zsh"

    ```bash
    # Add to ~/.zshrc (after compinit):
    source <(enstow completions zsh)

    # Or save to your fpath directory:
    enstow completions zsh > ~/.zfunc/_enstow
    # (Ensure fpath includes ~/.zfunc and autoload -Uz compinit && compinit is called)
    ```

=== "Fish"

    ```fish
    # Save to standard fish completion directory:
    enstow completions fish > ~/.config/fish/completions/enstow.fish

    # Or load directly in current session:
    enstow completions fish | source
    ```

=== "PowerShell"

    ```powershell
    # Append to your PowerShell profile:
    enstow completions powershell >> $PROFILE

    # Or load into active session:
    enstow completions powershell | Out-String | Invoke-Expression
    ```

=== "Elvish"

    ```elvish
    # Append to your Elvish rc:
    enstow completions elvish >> ~/.elvish/rc.elv

    # Or load into active session:
    eval (enstow completions elvish | slurp)
    ```

!!! tip
    Dynamic completions automatically service arguments, options, and package names on `<TAB>` via `clap_complete`. Pass `--static` to `enstow completions` to generate static fallback completion scripts instead.

Pre-generated completion scripts are also available in the [`completions/`](https://github.com/nicholaswilde/enstow/tree/main/completions) folder.

## :page_facing_up: Man Page

Generate or view the UNIX man page:

```bash
# Generate man page
task man
# Or with binary
enstow man > assets/enstow.1

# Preview formatted man page
man -l assets/enstow.1
```
