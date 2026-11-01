use clap::{Args, Parser, Subcommand};
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

    /// Explicit path to age identity key file
    #[arg(long, env = "SOPS_AGE_KEY_FILE")]
    pub age_key_file: Option<PathBuf>,

    /// Dotfile packages to stow or unstow
    #[arg(value_name = "PACKAGES")]
    pub packages: Vec<String>,

    /// Additional ignore patterns from config
    #[arg(skip)]
    pub ignore: Vec<String>,
}

impl CommonArgs {
    pub fn source_path(&self) -> &Path {
        self.source.as_deref().unwrap_or_else(|| Path::new("."))
    }

    pub fn target_path(&self) -> PathBuf {
        self.target.clone().unwrap_or_else(default_target_dir)
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
        #[arg(long, env = "SOPS_AGE_KEY_FILE")]
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
        #[arg(long, env = "SOPS_AGE_KEY_FILE")]
        age_key_file: Option<PathBuf>,

        /// Custom editor command to use instead of $VISUAL or $EDITOR
        #[arg(long)]
        editor: Option<String>,
    },
    /// Show status of dotfiles and symlinks
    Status {
        #[command(flatten)]
        common: CommonArgs,

        /// Output status in JSON format
        #[arg(long)]
        json: bool,
    },
}

pub fn default_target_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
