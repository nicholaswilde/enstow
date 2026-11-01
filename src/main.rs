mod cli;
mod crypto;
mod error;
mod stow;

use clap::Parser;
use cli::{Cli, Commands};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

fn main() -> anyhow::Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Apply(args)) => {
            let actions = stow::plan_stow(&args)?;
            stow::execute_plan(&actions, args.dry_run)?;
        }
        Some(Commands::Status(args)) => {
            let actions = stow::plan_stow(&args)?;
            stow::execute_plan(&actions, true)?;
        }
        Some(Commands::Encrypt { file }) => {
            println!("Encrypting {}", file.display());
            // TODO: Encryption implementation
        }
        None => {
            // Default to applying with root common args
            let actions = stow::plan_stow(&cli.common)?;
            stow::execute_plan(&actions, cli.common.dry_run)?;
        }
    }

    Ok(())
}
