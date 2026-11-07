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

    /// Adopt existing files into source package when conflicts occur
    #[arg(long)]
    pub adopt: bool,

    /// Explicit path to age identity key file
    #[arg(long, env = "ENSTOW_AGE_KEY_FILE")]
    pub age_key_file: Option<PathBuf>,

    /// Dotfile profile to select packages from configuration
    #[arg(long, env = "ENSTOW_PROFILE", value_name = "NAME")]
    pub profile: Option<String>,

    /// Dotfile packages to stow or unstow
    #[arg(value_name = "PACKAGES")]
    pub packages: Vec<String>,

    /// Additional pattern to ignore (can be specified multiple times)
    #[arg(short, long, value_name = "PATTERN")]
    pub ignore: Vec<String>,

    /// Skip execution of pre- and post-lifecycle hooks
    #[arg(long = "no-hooks", alias = "skip-hooks", env = "ENSTOW_NO_HOOKS")]
    pub no_hooks: bool,

    /// Securely shred decrypted secret files with zeros before unlinking
    #[arg(long, env = "ENSTOW_SHRED")]
    pub shred: bool,
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
    /// Add an existing target file to a package and replace it with a symlink or secret
    Add {
        /// Target file to add into the package
        file: PathBuf,

        /// Package to add the file to
        #[arg(short, long)]
        package: String,

        /// Encrypt the file into an age secret instead of storing plaintext
        #[arg(short = 'e', long)]
        encrypt: bool,

        /// Recipient public key(s) when encrypting
        #[arg(short, long)]
        recipient: Vec<String>,

        /// Explicit path to age identity key file
        #[arg(long, env = "ENSTOW_AGE_KEY_FILE")]
        age_key_file: Option<PathBuf>,

        /// Source directory containing dotfiles
        #[arg(short, long)]
        source: Option<PathBuf>,

        /// Target root directory
        #[arg(short, long)]
        target: Option<PathBuf>,

        /// Overwrite existing source files if they exist
        #[arg(short, long)]
        force: bool,

        /// Preview actions without writing changes to disk
        #[arg(short = 'n', long)]
        dry_run: bool,
    },
    /// Apply dotfiles: symlink regular files and decrypt secret files
    #[command(alias = "sync")]
    Apply(CommonArgs),
    /// Restow dotfiles: clean stale symlinks/secrets and re-apply
    Restow(CommonArgs),
    /// Unstow dotfiles: remove symlinks and decrypted secret files
    Unstow(CommonArgs),
    /// Scrub dotfiles: securely shred and remove decrypted secrets and symlinks
    Scrub(CommonArgs),
    /// Encrypt a secret dotfile
    Encrypt {
        /// File to encrypt
        file: PathBuf,

        /// Output encrypted file path (defaults to <file>.age)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Recipient public key(s)
        #[arg(short, long, conflicts_with = "passphrase")]
        recipient: Vec<String>,

        /// Explicit path to age identity key file to resolve recipient public key
        #[arg(long, env = "ENSTOW_AGE_KEY_FILE", conflicts_with = "passphrase")]
        age_key_file: Option<PathBuf>,

        /// Encrypt with a passphrase instead of recipient public keys
        #[arg(short = 'p', long)]
        passphrase: bool,
    },
    /// Decrypt a secret dotfile
    Decrypt {
        /// Encrypted file to decrypt
        file: PathBuf,

        /// Output decrypted file path (defaults to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Explicit path to age identity key file
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
    /// Re-encrypt age secret files with updated recipients across packages
    Rekey {
        /// Recipient public key(s)
        #[arg(short, long)]
        recipient: Vec<String>,

        /// Explicit path to age identity key file
        #[arg(long, env = "ENSTOW_AGE_KEY_FILE")]
        age_key_file: Option<PathBuf>,

        /// Preview files that would be re-encrypted without modifying them
        #[arg(short = 'n', long)]
        dry_run: bool,

        /// Source directory containing dotfiles
        #[arg(short, long)]
        source: Option<PathBuf>,

        /// Dotfile profile to select packages from configuration
        #[arg(long, env = "ENSTOW_PROFILE", value_name = "NAME")]
        profile: Option<String>,

        /// Additional pattern to ignore (can be specified multiple times)
        #[arg(short, long, value_name = "PATTERN")]
        ignore: Vec<String>,

        /// Dotfile packages to traverse for age secrets
        #[arg(value_name = "PACKAGES")]
        packages: Vec<String>,
    },
    /// Show status of dotfiles and symlinks
    Status {
        #[command(flatten)]
        common: CommonArgs,

        /// Output status in JSON format ($ENSTOW_JSON)
        #[arg(long)]
        json: bool,
    },
    /// Show diff between dotfiles and target destination
    Diff {
        #[command(flatten)]
        common: CommonArgs,

        /// Output diff in JSON format ($ENSTOW_JSON)
        #[arg(long)]
        json: bool,

        /// Mask sensitive secret contents in diff output
        #[arg(long, alias = "no-secrets")]
        mask_secrets: bool,
    },
    /// Check system health, secret hygiene, permissions, and symlinks
    #[command(alias = "lint")]
    Doctor {
        #[command(flatten)]
        common: CommonArgs,

        /// Output report in JSON format ($ENSTOW_JSON)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_target_dir() {
        let dir = default_target_dir();
        assert!(!dir.as_os_str().is_empty());
    }

    #[test]
    fn test_generate_manpage() {
        let mut buffer = Vec::new();
        let res = generate_manpage(&mut buffer);
        assert!(res.is_ok());
        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("enstow"));
    }

    #[test]
    fn test_generate_completions_all_shells() {
        for shell in [
            clap_complete::Shell::Bash,
            clap_complete::Shell::Zsh,
            clap_complete::Shell::Fish,
            clap_complete::Shell::PowerShell,
            clap_complete::Shell::Elvish,
        ] {
            let mut buf_dyn = Vec::new();
            assert!(generate_dynamic_completions(shell, &mut buf_dyn).is_ok());
            assert!(!buf_dyn.is_empty());

            let mut buf_stat = Vec::new();
            generate_static_completions(shell, &mut buf_stat);
            assert!(!buf_stat.is_empty());

            let mut buf_comp = Vec::new();
            generate_completions(shell, &mut buf_comp);
            assert!(!buf_comp.is_empty());
        }
    }

    #[test]
    fn test_cli_parsing_subcommands() {
        // apply
        let cli = Cli::try_parse_from(["enstow", "apply", "pkg1", "-n", "-f", "--prune"]).unwrap();
        match cli.command {
            Some(Commands::Apply(args)) => {
                assert!(args.dry_run);
                assert!(args.force);
                assert!(args.prune);
                assert_eq!(args.packages, vec!["pkg1"]);
            }
            _ => panic!("Expected Apply command"),
        }

        // unstow
        let cli = Cli::try_parse_from(["enstow", "unstow", "pkg1"]).unwrap();
        match cli.command {
            Some(Commands::Unstow(args)) => {
                assert_eq!(args.packages, vec!["pkg1"]);
            }
            _ => panic!("Expected Unstow command"),
        }

        // restow
        let cli = Cli::try_parse_from(["enstow", "restow", "pkg1", "--adopt"]).unwrap();
        match cli.command {
            Some(Commands::Restow(args)) => {
                assert!(args.adopt);
                assert_eq!(args.packages, vec!["pkg1"]);
            }
            _ => panic!("Expected Restow command"),
        }

        // diff
        let cli = Cli::try_parse_from(["enstow", "diff", "--mask-secrets", "--json"]).unwrap();
        match cli.command {
            Some(Commands::Diff {
                mask_secrets, json, ..
            }) => {
                assert!(mask_secrets);
                assert!(json);
            }
            _ => panic!("Expected Diff command"),
        }

        // doctor & lint alias
        let cli = Cli::try_parse_from(["enstow", "doctor", "--json"]).unwrap();
        match cli.command {
            Some(Commands::Doctor { json, .. }) => {
                assert!(json);
            }
            _ => panic!("Expected Doctor command"),
        }
        let cli_lint = Cli::try_parse_from(["enstow", "lint"]).unwrap();
        match cli_lint.command {
            Some(Commands::Doctor { json, .. }) => {
                assert!(!json);
            }
            _ => panic!("Expected Doctor command via lint alias"),
        }

        // status
        let cli = Cli::try_parse_from(["enstow", "status", "--json"]).unwrap();
        match cli.command {
            Some(Commands::Status { json, .. }) => {
                assert!(json);
            }
            _ => panic!("Expected Status command"),
        }

        // add
        let cli = Cli::try_parse_from([
            "enstow",
            "add",
            "my_target",
            "--package",
            "mypkg",
            "--encrypt",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Add {
                file,
                package,
                encrypt,
                ..
            }) => {
                assert_eq!(file, PathBuf::from("my_target"));
                assert_eq!(package, "mypkg");
                assert!(encrypt);
            }
            _ => panic!("Expected Add command"),
        }

        // encrypt
        let cli = Cli::try_parse_from(["enstow", "encrypt", "secret.txt", "-p"]).unwrap();
        match cli.command {
            Some(Commands::Encrypt {
                file, passphrase, ..
            }) => {
                assert_eq!(file, PathBuf::from("secret.txt"));
                assert!(passphrase);
            }
            _ => panic!("Expected Encrypt command"),
        }

        // decrypt
        let cli = Cli::try_parse_from(["enstow", "decrypt", "secret.age"]).unwrap();
        match cli.command {
            Some(Commands::Decrypt { file, .. }) => {
                assert_eq!(file, PathBuf::from("secret.age"));
            }
            _ => panic!("Expected Decrypt command"),
        }

        // rekey
        let cli = Cli::try_parse_from(["enstow", "rekey", "--recipient", "key1"]).unwrap();
        match cli.command {
            Some(Commands::Rekey { recipient, .. }) => {
                assert_eq!(recipient, vec!["key1"]);
            }
            _ => panic!("Expected Rekey command"),
        }

        // edit
        let cli = Cli::try_parse_from(["enstow", "edit", "secret.age"]).unwrap();
        match cli.command {
            Some(Commands::Edit { file, .. }) => {
                assert_eq!(file, PathBuf::from("secret.age"));
            }
            _ => panic!("Expected Edit command"),
        }

        // completions
        let cli = Cli::try_parse_from(["enstow", "completions", "bash", "--static"]).unwrap();
        match cli.command {
            Some(Commands::Completions {
                shell,
                static_completions,
            }) => {
                assert_eq!(shell, clap_complete::Shell::Bash);
                assert!(static_completions);
            }
            _ => panic!("Expected Completions command"),
        }

        // man
        let cli = Cli::try_parse_from(["enstow", "man"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Man)));
    }

    #[test]
    fn test_cli_verbose_quiet_conflict() {
        let err = Cli::try_parse_from(["enstow", "-v", "-q", "status"]).unwrap_err();
        assert!(err.to_string().contains("cannot be used with"));
    }
}
