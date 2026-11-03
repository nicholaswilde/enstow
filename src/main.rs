use clap::{CommandFactory, Parser};
use enstow::cli::{Cli, Commands};
use enstow::stow;

fn main() -> anyhow::Result<()> {
    clap_complete::CompleteEnv::with_factory(Cli::command)
        .completer("enstow")
        .complete();

    let cli = Cli::parse();
    let config = enstow::config::load_config(cli.config.as_deref())?.map(|(_, cfg)| cfg);
    let log_level = enstow::config::resolve_log_level(
        cli.log_level.as_deref(),
        cli.verbose,
        cli.quiet,
        config.as_ref(),
    );
    enstow::config::init_tracing(&log_level)?;
    tracing::debug!("Log level initialized to '{}'", log_level);

    match cli.command {
        Some(Commands::Apply(args)) => {
            let common =
                enstow::config::resolve_common_args(&args, config.as_ref())?.to_common_args();
            if common.prune {
                let stale_actions = stow::plan_prune(&common)?;
                stow::execute_unstow_plan(&stale_actions, &common.target_path(), common.dry_run)?;
            }
            let actions = stow::plan_stow(&common)?;
            stow::execute_plan_with_backup(
                &actions,
                common.dry_run,
                common.age_key_file.as_deref(),
                common.force,
                common.backup,
                Some(&common.backup_dir_path()),
                Some(&common.target_path()),
            )?;
        }
        Some(Commands::Restow(args)) => {
            let common =
                enstow::config::resolve_common_args(&args, config.as_ref())?.to_common_args();
            let unstow_actions = stow::plan_unstow(&common)?;
            stow::execute_unstow_plan(&unstow_actions, &common.target_path(), common.dry_run)?;
            let apply_actions = stow::plan_stow(&common)?;
            stow::execute_plan_with_backup(
                &apply_actions,
                common.dry_run,
                common.age_key_file.as_deref(),
                common.force,
                common.backup,
                Some(&common.backup_dir_path()),
                Some(&common.target_path()),
            )?;
        }
        Some(Commands::Unstow(args)) => {
            let common =
                enstow::config::resolve_common_args(&args, config.as_ref())?.to_common_args();
            let actions = stow::plan_unstow(&common)?;
            stow::execute_unstow_plan(&actions, &common.target_path(), common.dry_run)?;
        }
        Some(Commands::Status { common, json }) => {
            let resolved_common =
                enstow::config::resolve_common_args(&common, config.as_ref())?.to_common_args();
            let json = enstow::config::resolve_json(json, config.as_ref());
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
        Some(Commands::Diff {
            common,
            json,
            mask_secrets,
        }) => {
            let resolved_common =
                enstow::config::resolve_common_args(&common, config.as_ref())?.to_common_args();
            let json = enstow::config::resolve_json(json, config.as_ref());
            let mask_secrets = enstow::config::resolve_mask_secrets(mask_secrets, config.as_ref());
            let actions = stow::plan_stow(&resolved_common)?;
            let diffs = enstow::diff::compute_diff(
                &actions,
                resolved_common.age_key_file.as_deref(),
                mask_secrets,
            )?;
            if json {
                println!("{}", serde_json::to_string_pretty(&diffs)?);
            } else {
                use std::io::IsTerminal;
                let colorize =
                    std::io::stdout().is_terminal() && std::env::var("NO_COLOR").is_err();
                for file_diff in &diffs {
                    if colorize {
                        print!("{}", enstow::diff::colorize_diff(&file_diff.diff));
                    } else {
                        print!("{}", file_diff.diff);
                    }
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
        Some(Commands::Man) => {
            let mut stdout = std::io::stdout().lock();
            enstow::cli::generate_manpage(&mut stdout)?;
        }
        Some(Commands::Completions {
            shell,
            static_completions,
        }) => {
            let mut stdout = std::io::stdout().lock();
            if static_completions {
                enstow::cli::generate_static_completions(shell, &mut stdout);
            } else {
                enstow::cli::generate_completions(shell, &mut stdout);
            }
        }
        None => {
            // Default to applying with root common args
            let common =
                enstow::config::resolve_common_args(&cli.common, config.as_ref())?.to_common_args();
            let actions = stow::plan_stow(&common)?;
            stow::execute_plan_with_backup(
                &actions,
                common.dry_run,
                common.age_key_file.as_deref(),
                common.force,
                common.backup,
                Some(&common.backup_dir_path()),
                Some(&common.target_path()),
            )?;
        }
    }

    Ok(())
}
