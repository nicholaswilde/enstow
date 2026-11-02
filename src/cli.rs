use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::env::EnvCompleter;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "enstow",
    author = "Nicholas Wilde",
    version,
    about = "Secret-aware dotfile manager combining stow symlinking with sops/age decryption"
)]
pub struct Cli {
    /// Path to configuration file (TOML, YAML, or JSON)
    #[arg(short = 'C', long, global = true, env = "ENSTOW_CONFIG")]
    pub config: Option<PathBuf>,

    /// Log level filter (trace, debug, info, warn, error, off)
    #[arg(long, global = true, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Verbose output (-v for debug, -vv for trace)
    #[arg(
        short = 'v',
        long,
        action = clap::ArgAction::Count,
        global = true,
        conflicts_with = "quiet"
    )]
    pub verbose: u8,

    /// Quiet mode (-q for warn, -qq for error)
    #[arg(
        short = 'q',
        long,
        action = clap::ArgAction::Count,
        global = true,
        conflicts_with = "verbose"
    )]
    pub quiet: u8,

    #[command(subcommand)]
    pub command: Option<Commands>,

    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Args, Debug, Clone, PartialEq, Eq, Default)]
pub struct CommonArgs {
    /// Source directory containing dotfiles
    #[arg(short, long)]
    pub source: Option<PathBuf>,

    /// Target directory to apply dotfiles
    #[arg(short, long)]
    pub target: Option<PathBuf>,

    /// Preview actions without writing changes to disk
    #[arg(short = 'n', long)]
    pub dry_run: bool,

    /// Overwrite existing target files or differing symlinks
    #[arg(short, long)]
    pub force: bool,

    /// Backup conflicting target files before overwriting
    #[arg(short = 'b', long)]
    pub backup: bool,

    /// Directory to relocate conflicting target files during backup
    #[arg(long, value_name = "PATH")]
    pub backup_dir: Option<PathBuf>,

    /// Prune stale symlinks for managed packages during apply
    #[arg(long)]
    pub prune: bool,

    /// Explicit path to age identity key file
    #[arg(long, env = "ENSTOW_AGE_KEY_FILE")]
    pub age_key_file: Option<PathBuf>,

    /// Dotfile packages to stow or unstow
    #[arg(value_name = "PACKAGES")]
    pub packages: Vec<String>,

    /// Additional pattern to ignore (can be specified multiple times)
    #[arg(short, long, value_name = "PATTERN")]
    pub ignore: Vec<String>,
}

impl CommonArgs {
    pub fn source_path(&self) -> &Path {
        self.source.as_deref().unwrap_or_else(|| Path::new("."))
    }

    pub fn target_path(&self) -> PathBuf {
        self.target.clone().unwrap_or_else(default_target_dir)
    }

    pub fn backup_dir_path(&self) -> PathBuf {
        self.backup_dir
            .clone()
            .unwrap_or_else(|| self.target_path().join(".enstow-backup"))
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Apply dotfiles: symlink regular files and decrypt secret files
    Apply(CommonArgs),
    /// Restow dotfiles: clean stale symlinks/secrets and re-apply
    Restow(CommonArgs),
    /// Unstow dotfiles: remove symlinks and decrypted secret files
    Unstow(CommonArgs),
    /// Encrypt a secret dotfile
    Encrypt {
        /// File to encrypt
        file: PathBuf,

        /// Output encrypted file path (defaults to <file>.age)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Recipient public key(s)
        #[arg(short, long)]
        recipient: Vec<String>,

        /// Explicit path to age identity key file to resolve recipient public key
        #[arg(long, env = "ENSTOW_AGE_KEY_FILE")]
        age_key_file: Option<PathBuf>,
    },
    /// Edit an age encrypted secret file interactively
    Edit {
        /// Encrypted age secret file to edit
        file: PathBuf,

        /// Recipient public key(s)
        #[arg(short, long)]
        recipient: Vec<String>,

        /// Explicit path to age identity key file to resolve recipient public key
        #[arg(long, env = "ENSTOW_AGE_KEY_FILE")]
        age_key_file: Option<PathBuf>,

        /// Custom editor command to use instead of $ENSTOW_EDITOR, $VISUAL, or $EDITOR
        #[arg(long)]
        editor: Option<String>,
    },
    /// Show status of dotfiles and symlinks
    Status {
        #[command(flatten)]
        common: CommonArgs,

        /// Output status in JSON format ($ENSTOW_JSON)
        #[arg(long)]
        json: bool,
    },
    /// Generate UNIX roff man page
    Man,
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
        /// Generate static autocompletions script instead of dynamic
        #[arg(long = "static")]
        static_completions: bool,
    },
}

pub fn default_target_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn generate_manpage(writer: &mut dyn Write) -> anyhow::Result<()> {
    let cmd = Cli::command();
    let man = clap_mangen::Man::new(cmd);
    man.render(writer)
        .map_err(|e| anyhow::anyhow!("Failed rendering man page: {e}"))
}

/// Generate dynamic registration completion script for the requested shell.
pub fn generate_dynamic_completions(
    shell: clap_complete::Shell,
    writer: &mut dyn Write,
) -> std::io::Result<()> {
    match shell {
        clap_complete::Shell::Bash => clap_complete::env::Bash
            .write_registration("COMPLETE", "enstow", "enstow", "enstow", writer),
        clap_complete::Shell::Zsh => clap_complete::env::Zsh
            .write_registration("COMPLETE", "enstow", "enstow", "enstow", writer),
        clap_complete::Shell::Fish => clap_complete::env::Fish
            .write_registration("COMPLETE", "enstow", "enstow", "enstow", writer),
        clap_complete::Shell::PowerShell => clap_complete::env::Powershell
            .write_registration("COMPLETE", "enstow", "enstow", "enstow", writer),
        clap_complete::Shell::Elvish => clap_complete::env::Elvish
            .write_registration("COMPLETE", "enstow", "enstow", "enstow", writer),
        _ => Err(std::io::Error::other(format!(
            "Unsupported shell for dynamic completions: {shell}"
        ))),
    }
}

/// Generate static completion script for the requested shell.
pub fn generate_static_completions(shell: clap_complete::Shell, writer: &mut dyn Write) {
    let mut cmd = Cli::command();
    let bin_name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, bin_name, writer);
}

/// Generate shell completions, attempting dynamic registration first and falling back to static generation.
pub fn generate_completions(shell: clap_complete::Shell, writer: &mut dyn Write) {
    if generate_dynamic_completions(shell, writer).is_err() {
        generate_static_completions(shell, writer);
    }
}
