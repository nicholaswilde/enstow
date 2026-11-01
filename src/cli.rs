use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "enstow",
    author = "Nicholas Wilde",
    version,
    about = "Secret-aware dotfile manager combining stow symlinking with sops/age decryption"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[command(flatten)]
    pub common: CommonArgs,
}

#[derive(Args, Debug, Clone)]
pub struct CommonArgs {
    /// Source directory containing dotfiles
    #[arg(short, long, default_value = ".")]
    pub source: PathBuf,

    /// Target directory to apply dotfiles
    #[arg(short, long, default_value_os_t = default_target_dir())]
    pub target: PathBuf,

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
}

impl Default for CommonArgs {
    fn default() -> Self {
        Self {
            source: PathBuf::from("."),
            target: default_target_dir(),
            dry_run: false,
            force: false,
            age_key_file: None,
            packages: Vec::new(),
        }
    }
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Apply dotfiles: symlink regular files and decrypt secret files
    Apply(CommonArgs),
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
    /// Show status of dotfiles and symlinks
    Status {
        #[command(flatten)]
        common: CommonArgs,

        /// Output status in JSON format
        #[arg(long)]
        json: bool,
    },
}

fn default_target_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}
