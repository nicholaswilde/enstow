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
    let config = enstow::config::load_config(cli.config.as_deref())?.map(|(_, cfg)| cfg);

    match cli.command {
        Some(Commands::Apply(args)) => {
            let common =
                enstow::config::resolve_common_args(&args, config.as_ref()).to_common_args();
            let actions = stow::plan_stow(&common)?;
            stow::execute_plan(
                &actions,
                common.dry_run,
                common.age_key_file.as_deref(),
                common.force,
            )?;
        }
        Some(Commands::Restow(args)) => {
            let common =
                enstow::config::resolve_common_args(&args, config.as_ref()).to_common_args();
            let unstow_actions = stow::plan_unstow(&common)?;
            stow::execute_unstow_plan(&unstow_actions, &common.target_path(), common.dry_run)?;
            let apply_actions = stow::plan_stow(&common)?;
            stow::execute_plan(
                &apply_actions,
                common.dry_run,
                common.age_key_file.as_deref(),
                common.force,
            )?;
        }
        Some(Commands::Unstow(args)) => {
            let common =
                enstow::config::resolve_common_args(&args, config.as_ref()).to_common_args();
            let actions = stow::plan_unstow(&common)?;
            stow::execute_unstow_plan(&actions, &common.target_path(), common.dry_run)?;
        }
        Some(Commands::Status { common, json }) => {
            let resolved_common =
                enstow::config::resolve_common_args(&common, config.as_ref()).to_common_args();
            let actions = stow::plan_stow(&resolved_common)?;
            let statuses = stow::check_status(&actions, resolved_common.age_key_file.as_deref())?;
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
            let resolved_recipients =
                enstow::config::resolve_recipients(&recipient, config.as_ref());
            let resolved_key_file =
                enstow::config::resolve_age_key_file(age_key_file.as_deref(), config.as_ref());
            let out = output.unwrap_or_else(|| {
                let mut p = file.as_os_str().to_os_string();
                p.push(".age");
                std::path::PathBuf::from(p)
            });
            enstow::crypto::encrypt_file_age(
                &file,
                &out,
                &resolved_recipients,
                resolved_key_file.as_deref(),
            )?;
            println!("Encrypted {} -> {}", file.display(), out.display());
        }
        Some(Commands::Edit {
            file,
            recipient,
            age_key_file,
            editor,
        }) => {
            let resolved_recipients =
                enstow::config::resolve_recipients(&recipient, config.as_ref());
            let resolved_key_file =
                enstow::config::resolve_age_key_file(age_key_file.as_deref(), config.as_ref());
            let resolved_editor =
                enstow::config::resolve_editor(editor.as_deref(), config.as_ref());
            let modified = enstow::crypto::edit_file_age(
                &file,
                &resolved_recipients,
                resolved_key_file.as_deref(),
                resolved_editor.as_deref(),
            )?;
            if modified {
                println!("Saved and re-encrypted {}", file.display());
            } else {
                println!("No changes made to {}", file.display());
            }
        }
        None => {
            // Default to applying with root common args
            let common =
                enstow::config::resolve_common_args(&cli.common, config.as_ref()).to_common_args();
            let actions = stow::plan_stow(&common)?;
            stow::execute_plan(
                &actions,
                common.dry_run,
                common.age_key_file.as_deref(),
                common.force,
            )?;
        }
    }

    Ok(())
}
