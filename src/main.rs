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
        Some(Commands::Add {
            file,
            package,
            encrypt,
            recipient,
            age_key_file,
            source,
            target,
            force,
            dry_run,
        }) => {
            let resolved_source =
                enstow::config::resolve_source(source.as_deref(), config.as_ref());
            let resolved_target =
                enstow::config::resolve_target(target.as_deref(), config.as_ref());
            let resolved_recipients =
                enstow::config::resolve_recipients(&recipient, config.as_ref());
            let resolved_key_file =
                enstow::config::resolve_age_key_file(age_key_file.as_deref(), config.as_ref());
            let resolved_dry_run = enstow::config::resolve_dry_run(dry_run, config.as_ref());
            let resolved_force = if force {
                true
            } else if let Some(env_force) = enstow::config::parse_bool_env("ENSTOW_FORCE") {
                env_force
            } else {
                config.as_ref().and_then(|c| c.force).unwrap_or_default()
            };

            let (target_p, source_p) = enstow::stow::add_file(
                &file,
                &package,
                encrypt,
                &resolved_recipients,
                resolved_key_file.as_deref(),
                &resolved_source,
                &resolved_target,
                resolved_force,
                resolved_dry_run,
            )?;

            if !resolved_dry_run {
                if encrypt {
                    println!(
                        "Added and encrypted {} -> {}",
                        target_p.display(),
                        source_p.display()
                    );
                } else {
                    println!("Added {} -> {}", target_p.display(), source_p.display());
                }
            }
        }
        Some(Commands::Apply(args)) => {
            let resolved = enstow::config::resolve_common_args(&args, config.as_ref())?;
            let common = resolved.to_common_args();
            if common.prune {
                let stale_actions = stow::plan_prune(&common)?;
                stow::execute_unstow_plan_with_shred(
                    &stale_actions,
                    &common.target_path(),
                    common.dry_run,
                    common.shred,
                )?;
            }
            let actions = stow::plan_stow(&common)?;
            enstow::hook::run_pre_apply_hooks(&resolved)?;
            stow::execute_plan_with_backup_and_permissions(
                &actions,
                common.dry_run,
                common.age_key_file.as_deref(),
                common.force,
                common.backup,
                Some(&common.backup_dir_path()),
                Some(&common.target_path()),
                Some(&resolved.permissions),
                common.adopt,
            )?;
            enstow::hook::run_post_apply_hooks(&resolved)?;
        }
        Some(Commands::Restow(args)) => {
            let resolved = enstow::config::resolve_common_args(&args, config.as_ref())?;
            let common = resolved.to_common_args();
            enstow::hook::run_pre_unstow_hooks(&resolved)?;
            let unstow_actions = stow::plan_unstow(&common)?;
            stow::execute_unstow_plan_with_shred(
                &unstow_actions,
                &common.target_path(),
                common.dry_run,
                common.shred,
            )?;
            enstow::hook::run_post_unstow_hooks(&resolved)?;

            enstow::hook::run_pre_apply_hooks(&resolved)?;
            let apply_actions = stow::plan_stow(&common)?;
            stow::execute_plan_with_backup_and_permissions(
                &apply_actions,
                common.dry_run,
                common.age_key_file.as_deref(),
                common.force,
                common.backup,
                Some(&common.backup_dir_path()),
                Some(&common.target_path()),
                Some(&resolved.permissions),
                common.adopt,
            )?;
            enstow::hook::run_post_apply_hooks(&resolved)?;
        }
        Some(Commands::Unstow(args)) => {
            let resolved = enstow::config::resolve_common_args(&args, config.as_ref())?;
            let common = resolved.to_common_args();
            enstow::hook::run_pre_unstow_hooks(&resolved)?;
            let actions = stow::plan_unstow(&common)?;
            stow::execute_unstow_plan_with_shred(
                &actions,
                &common.target_path(),
                common.dry_run,
                common.shred,
            )?;
            enstow::hook::run_post_unstow_hooks(&resolved)?;
        }
        Some(Commands::Scrub(mut args)) => {
            args.shred = true;
            let resolved = enstow::config::resolve_common_args(&args, config.as_ref())?;
            let mut common = resolved.to_common_args();
            common.shred = true;
            enstow::hook::run_pre_unstow_hooks(&resolved)?;
            let actions = stow::plan_unstow(&common)?;
            stow::execute_unstow_plan_with_shred(
                &actions,
                &common.target_path(),
                common.dry_run,
                true,
            )?;
            enstow::hook::run_post_unstow_hooks(&resolved)?;
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
            passphrase,
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
                passphrase,
            )?;
            println!("Encrypted {} -> {}", file.display(), out.display());
        }
        Some(Commands::Decrypt {
            file,
            output,
            age_key_file,
        }) => {
            let resolved_key_file =
                enstow::config::resolve_age_key_file(age_key_file.as_deref(), config.as_ref());
            let secret_type = enstow::crypto::detect_secret_type(&file).ok_or_else(|| {
                enstow::error::EnstowError::Config(format!(
                    "Unrecognized secret format: {}",
                    file.display()
                ))
            })?;
            let plaintext = enstow::crypto::decrypt_to_memory(
                &file,
                secret_type,
                resolved_key_file.as_deref(),
            )?;
            if let Some(out_path) = output {
                enstow::crypto::write_secure_file(&out_path, &plaintext, true)?;
                println!("Decrypted {} -> {}", file.display(), out_path.display());
            } else {
                use std::io::Write;
                std::io::stdout().write_all(&plaintext)?;
            }
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
        Some(Commands::Rekey {
            recipient,
            age_key_file,
            dry_run,
            source,
            profile,
            ignore,
            packages,
        }) => {
            let resolved_source = enstow::config::resolve_source(
                source.as_deref().or(cli.common.source.as_deref()),
                config.as_ref(),
            );
            let resolved_recipients =
                enstow::config::resolve_recipients(&recipient, config.as_ref());
            let resolved_key_file = enstow::config::resolve_age_key_file(
                age_key_file
                    .as_deref()
                    .or(cli.common.age_key_file.as_deref()),
                config.as_ref(),
            );
            let resolved_dry_run =
                enstow::config::resolve_dry_run(dry_run || cli.common.dry_run, config.as_ref());
            let resolved_packages = enstow::config::resolve_packages(
                if !packages.is_empty() {
                    &packages
                } else {
                    &cli.common.packages
                },
                profile.as_deref().or(cli.common.profile.as_deref()),
                config.as_ref(),
            )?;
            let mut all_ignores = cli.common.ignore.clone();
            all_ignores.extend(ignore);
            let resolved_ignore =
                enstow::config::resolve_ignore_patterns(&all_ignores, config.as_ref());

            enstow::crypto::rekey_packages(
                &resolved_source,
                &resolved_packages,
                &resolved_ignore,
                &resolved_recipients,
                resolved_key_file.as_deref(),
                resolved_dry_run,
            )?;
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
            let resolved = enstow::config::resolve_common_args(&cli.common, config.as_ref())?;
            let common = resolved.to_common_args();
            let actions = stow::plan_stow(&common)?;
            enstow::hook::run_pre_apply_hooks(&resolved)?;
            stow::execute_plan_with_backup_and_permissions(
                &actions,
                common.dry_run,
                common.age_key_file.as_deref(),
                common.force,
                common.backup,
                Some(&common.backup_dir_path()),
                Some(&common.target_path()),
                Some(&resolved.permissions),
                common.adopt,
            )?;
            enstow::hook::run_post_apply_hooks(&resolved)?;
        }
    }

    Ok(())
}
