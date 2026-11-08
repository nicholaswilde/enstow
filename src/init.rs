use std::fs;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::info;

use crate::cli::{CommonArgs, InitArgs};
use crate::config::{
    detect_host_packages, detect_host_profile, discover_repo_config, resolve_age_key_file,
    resolve_common_args, resolve_dry_run, resolve_init_source, resolve_packages_for_host,
    resolve_profile, resolve_target, set_active_profile, ConfigFile, HostInfo, ResolvedCommonArgs,
};
use crate::crypto::{default_age_key_file, find_existing_age_key, import_age_key};
use crate::doctor::{run_doctor, CheckSeverity, DoctorReport};
use crate::error::EnstowError;
use crate::hook::{run_post_apply_hooks, run_pre_apply_hooks};
use crate::stow::{
    execute_plan_interactive_with_io, execute_unstow_plan_with_shred, normalize_path, plan_prune,
    plan_stow, FileAction,
};

/// Summary report returned after executing `enstow init`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InitReport {
    pub source: PathBuf,
    pub target: PathBuf,
    pub cloned: bool,
    pub host: HostInfo,
    pub profile: Option<String>,
    pub packages: Vec<String>,
    pub age_key_file: Option<PathBuf>,
    pub doctor: DoctorReport,
    pub applied_actions: usize,
}

fn prepare_clone_dest(dest: &Path, force: bool, dry_run: bool) -> Result<(), EnstowError> {
    if !dest.exists() && fs::symlink_metadata(dest).is_err() {
        return Ok(());
    }
    let is_empty_dir = dest.is_dir()
        && fs::read_dir(dest)
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);
    if is_empty_dir {
        return Ok(());
    }
    if !force {
        return Err(EnstowError::Collision {
            path: dest.to_path_buf(),
        });
    }
    if !dry_run {
        if dest.is_dir() {
            fs::remove_dir_all(dest).map_err(|e| EnstowError::Io {
                path: dest.to_path_buf(),
                source: e,
            })?;
        } else {
            fs::remove_file(dest).map_err(|e| EnstowError::Io {
                path: dest.to_path_buf(),
                source: e,
            })?;
        }
    }
    Ok(())
}

fn invoke_git_clone(repo: &str, dest: &Path, branch: Option<&str>) -> Result<(), EnstowError> {
    if let Some(parent) = dest.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|e| EnstowError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let mut cmd = Command::new("git");
    cmd.arg("clone");
    if let Some(b) = branch.map(str::trim).filter(|s| !s.is_empty()) {
        cmd.arg("--branch").arg(b);
    }
    cmd.arg(repo).arg(dest);

    let output = cmd.output().map_err(|e| {
        EnstowError::Config(format!("Failed to execute `git clone` for '{repo}': {e}"))
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(EnstowError::Config(format!(
            "Failed to clone repository '{}': {}",
            repo,
            stderr.trim()
        )));
    }
    Ok(())
}

/// Clone a git repository into `dest` if not already cloned.
pub fn clone_repository(
    repo: &str,
    dest: &Path,
    branch: Option<&str>,
    force: bool,
    dry_run: bool,
) -> Result<bool, EnstowError> {
    if dest.join(".git").exists() {
        info!(
            "Repository already exists at '{}', skipping clone",
            dest.display()
        );
        return Ok(false);
    }

    prepare_clone_dest(dest, force, dry_run)?;
    if dry_run {
        println!("[dry-run] CLONE {} -> {}", repo, dest.display());
        return Ok(true);
    }

    invoke_git_clone(repo, dest, branch)?;
    Ok(true)
}

fn check_or_import_age_key<R: BufRead, W: Write>(
    explicit_key: Option<&Path>,
    dry_run: bool,
    reader: &mut R,
    writer: &mut W,
) -> Result<Option<PathBuf>, EnstowError> {
    if let Some(existing) = find_existing_age_key(explicit_key) {
        info!("Found age identity key at '{}'", existing.display());
        return Ok(Some(existing));
    }

    let dest_key_path = explicit_key
        .map(Path::to_path_buf)
        .unwrap_or_else(default_age_key_file);

    let _ = write!(
        writer,
        "No age identity key found. Enter age secret key or path to key file to import (press Enter to skip): "
    );
    let _ = writer.flush();

    let mut line = String::new();
    let bytes_read = reader.read_line(&mut line).map_err(|e| EnstowError::Io {
        path: dest_key_path.clone(),
        source: e,
    })?;

    if bytes_read == 0 || line.trim().is_empty() {
        return Ok(None);
    }

    let imported = import_age_key(line.trim(), &dest_key_path, dry_run)?;
    Ok(Some(imported))
}

fn resolve_init_common(
    args: &InitArgs,
    effective_source: &Path,
    discovered_cfg_file: Option<&Path>,
    effective_config: Option<&ConfigFile>,
    host: &HostInfo,
) -> Result<ResolvedCommonArgs, EnstowError> {
    let mut common_input = CommonArgs {
        source: Some(effective_source.to_path_buf()),
        ..Default::default()
    };
    common_input.target.clone_from(&args.target);
    common_input.dry_run = args.dry_run;
    common_input.force = args.force;
    common_input.backup = args.backup;
    common_input.backup_dir.clone_from(&args.backup_dir);
    common_input.prune = args.prune;
    common_input.adopt = args.adopt;
    common_input.interactive = args.interactive;
    common_input.age_key_file.clone_from(&args.age_key_file);
    common_input.profile = args
        .profile
        .clone()
        .or_else(|| detect_host_profile(effective_config, host));
    common_input.packages.clone_from(&args.packages);
    common_input.ignore.clone_from(&args.ignore);
    common_input.no_hooks = args.no_hooks;
    common_input.shred = args.shred;

    if let Some(fname) = discovered_cfg_file
        .filter(|p| p.parent() == Some(effective_source))
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
    {
        let pat = format!("/{fname}");
        if !common_input.ignore.contains(&pat) {
            common_input.ignore.push(pat);
        }
    }

    let mut resolved = resolve_common_args(&common_input, effective_config)
        .map_err(|e| EnstowError::Config(e.to_string()))?;

    resolved.packages = resolve_packages_for_host(
        &common_input.packages,
        common_input.profile.as_deref(),
        effective_config,
        host,
    )
    .map_err(|e| EnstowError::Config(e.to_string()))?;

    let had_configured_pkgs = !common_input.packages.is_empty()
        || common_input.profile.is_some()
        || effective_config
            .and_then(|c| c.packages.as_ref())
            .is_some_and(|p| !p.is_empty())
        || effective_config
            .and_then(|c| c.default_profile.as_ref())
            .is_some();

    if !had_configured_pkgs && resolved.packages.is_empty() {
        resolved.packages = detect_host_packages(effective_source, effective_config, host);
    }

    resolved.profile = resolve_profile(common_input.profile.as_deref(), effective_config);
    set_active_profile(resolved.profile.clone());
    Ok(resolved)
}

fn remap_staging_sources(actions: &mut [FileAction], staging: &Path, dest_source: &Path) {
    let staging_canon = staging
        .canonicalize()
        .map(|p| normalize_path(&p))
        .unwrap_or_else(|_| normalize_path(staging));
    for action in actions {
        let (FileAction::Symlink { source, .. } | FileAction::Decrypt { source, .. }) = action;
        if let Ok(rel) = source
            .strip_prefix(&staging_canon)
            .or_else(|_| source.strip_prefix(staging))
        {
            *source = dest_source.join(rel);
        }
    }
}

/// Run `enstow init` using the current host environment and standard I/O streams.
pub fn run_init(args: &InitArgs, config: Option<&ConfigFile>) -> Result<InitReport, EnstowError> {
    if std::io::stdin().is_terminal() && !args.interactive {
        let mut empty = std::io::empty();
        let mut sink = std::io::stderr();
        return run_init_with_io(args, config, None, &mut empty, &mut sink);
    }
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut writer = std::io::stderr();
    run_init_with_io(args, config, None, &mut reader, &mut writer)
}

/// Run `enstow init` with custom `BufRead`, `Write`, and optional `HostInfo`.
pub fn run_init_with_io<R: BufRead, W: Write>(
    args: &InitArgs,
    config: Option<&ConfigFile>,
    host_override: Option<&HostInfo>,
    reader: &mut R,
    writer: &mut W,
) -> Result<InitReport, EnstowError> {
    let current_host = HostInfo::current();
    let host = host_override.unwrap_or(&current_host);
    let source_dir = resolve_init_source(args.source.as_deref(), config);
    let initial_dry_run = resolve_dry_run(args.dry_run, config);
    let initial_force = args.force
        || crate::config::parse_bool_env("ENSTOW_FORCE")
            .unwrap_or_else(|| config.and_then(|c| c.force).unwrap_or_default());

    let mut temp_staging = None;
    let cloned = if let Some(repo) = &args.repo {
        let did_clone = clone_repository(
            repo,
            &source_dir,
            args.branch.as_deref(),
            initial_force,
            initial_dry_run,
        )?;
        if initial_dry_run && !source_dir.exists() {
            if let Ok(staging) = tempfile::tempdir() {
                if invoke_git_clone(repo, staging.path(), args.branch.as_deref()).is_ok() {
                    temp_staging = Some(staging);
                }
            }
        }
        did_clone
    } else if source_dir.exists() {
        false
    } else {
        return Err(EnstowError::Config(format!(
            "Source directory '{}' does not exist and no repository URL was provided",
            source_dir.display()
        )));
    };

    let effective_source = temp_staging
        .as_ref()
        .map(|t| t.path().to_path_buf())
        .unwrap_or_else(|| source_dir.clone());

    let discovered = if config.is_none() && effective_source.is_dir() {
        discover_repo_config(&effective_source).map_err(|e| EnstowError::Config(e.to_string()))?
    } else {
        None
    };
    let effective_config = config.or_else(|| discovered.as_ref().map(|(_, c)| c));

    if !effective_source.exists() {
        let dry_run = resolve_dry_run(args.dry_run, effective_config);
        let candidate_key = resolve_age_key_file(args.age_key_file.as_deref(), effective_config);
        let age_key_file =
            check_or_import_age_key(candidate_key.as_deref(), dry_run, reader, writer)?;
        return Ok(InitReport {
            source: source_dir,
            target: resolve_target(args.target.as_deref(), effective_config),
            cloned,
            host: host.clone(),
            profile: args
                .profile
                .clone()
                .or_else(|| detect_host_profile(effective_config, host)),
            packages: args.packages.clone(),
            age_key_file,
            doctor: DoctorReport::new(Vec::new()),
            applied_actions: 0,
        });
    }

    let mut resolved = resolve_init_common(
        args,
        &effective_source,
        discovered.as_ref().map(|(p, _)| p.as_path()),
        effective_config,
        host,
    )?;

    if let Some(key) = check_or_import_age_key(
        resolved.age_key_file.as_deref(),
        resolved.dry_run,
        reader,
        writer,
    )? {
        resolved.age_key_file = Some(key);
    }

    let common = resolved.to_common_args();
    let doctor_report = run_doctor(&common, Some(&resolved.permissions))?;
    if !doctor_report.healthy && !common.dry_run {
        let errs: Vec<&str> = doctor_report
            .checks
            .iter()
            .filter(|c| c.severity == CheckSeverity::Error)
            .map(|c| c.message.as_str())
            .collect();
        return Err(EnstowError::Config(format!(
            "Pre-flight check failed with {} error(s): {}",
            doctor_report.errors,
            errs.join("; ")
        )));
    }

    if common.prune && common.target_path().exists() {
        let stale = plan_prune(&common)?;
        execute_unstow_plan_with_shred(
            &stale,
            &common.target_path(),
            common.dry_run,
            common.shred,
        )?;
    }

    let mut actions = plan_stow(&common)?;
    if let Some(staging) = &temp_staging {
        remap_staging_sources(&mut actions, staging.path(), &source_dir);
    }

    if !common.dry_run {
        run_pre_apply_hooks(&resolved)?;
    }
    execute_plan_interactive_with_io(
        &actions,
        common.dry_run,
        common.age_key_file.as_deref(),
        common.force,
        common.backup,
        Some(&common.backup_dir_path()),
        Some(&common.target_path()),
        Some(&resolved.permissions),
        common.adopt,
        common.interactive,
        reader,
        writer,
        false,
    )?;
    if !common.dry_run {
        run_post_apply_hooks(&resolved)?;
    }

    Ok(InitReport {
        source: source_dir,
        target: common.target_path(),
        cloned,
        host: host.clone(),
        profile: resolved.profile,
        packages: resolved.packages,
        age_key_file: common.age_key_file,
        doctor: doctor_report,
        applied_actions: actions.len(),
    })
}
