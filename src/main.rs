use clap::Parser;
use enstow::cli::{Cli, Commands};
use enstow::stow;
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
            stow::execute_plan(
                &actions,
                args.dry_run,
                args.age_key_file.as_deref(),
                args.force,
            )?;
        }
        Some(Commands::Restow(args)) => {
            let unstow_actions = stow::plan_unstow(&args)?;
            stow::execute_unstow_plan(&unstow_actions, &args.target, args.dry_run)?;
            let apply_actions = stow::plan_stow(&args)?;
            stow::execute_plan(
                &apply_actions,
                args.dry_run,
                args.age_key_file.as_deref(),
                args.force,
            )?;
        }
        Some(Commands::Unstow(args)) => {
            let actions = stow::plan_unstow(&args)?;
            stow::execute_unstow_plan(&actions, &args.target, args.dry_run)?;
        }
        Some(Commands::Status { common, json }) => {
            let actions = stow::plan_stow(&common)?;
            let statuses = stow::check_status(&actions, common.age_key_file.as_deref())?;
            if json {
                println!("{}", serde_json::to_string_pretty(&statuses)?);
            } else {
                for item in statuses {
                    let status_str = match item.status {
                        stow::EntryStatus::Synced => "\x1b[32mSYNCED\x1b[0m    ",
                        stow::EntryStatus::Missing => "\x1b[33mMISSING\x1b[0m   ",
                        stow::EntryStatus::Conflict => "\x1b[31mCONFLICT\x1b[0m  ",
                        stow::EntryStatus::Modified => "\x1b[35mMODIFIED\x1b[0m  ",
                        stow::EntryStatus::Unverified => "\x1b[36mUNVERIFIED\x1b[0m",
                    };
                    println!(
                        "{} {} -> {}",
                        status_str,
                        item.action.target().display(),
                        item.action.source().display()
                    );
                }
            }
        }
        Some(Commands::Encrypt {
            file,
            output,
            recipient,
            age_key_file,
        }) => {
            let out = output.unwrap_or_else(|| {
                let mut p = file.as_os_str().to_os_string();
                p.push(".age");
                std::path::PathBuf::from(p)
            });
            enstow::crypto::encrypt_file_age(&file, &out, &recipient, age_key_file.as_deref())?;
            println!("Encrypted {} -> {}", file.display(), out.display());
        }
        Some(Commands::Edit {
            file,
            recipient,
            age_key_file,
            editor,
        }) => {
            let modified = enstow::crypto::edit_file_age(
                &file,
                &recipient,
                age_key_file.as_deref(),
                editor.as_deref(),
            )?;
            if modified {
                println!("Saved and re-encrypted {}", file.display());
            } else {
                println!("No changes made to {}", file.display());
            }
        }
        None => {
            // Default to applying with root common args
            let actions = stow::plan_stow(&cli.common)?;
            stow::execute_plan(
                &actions,
                cli.common.dry_run,
                cli.common.age_key_file.as_deref(),
                cli.common.force,
            )?;
        }
    }

    Ok(())
}
