use crate::cli::CommonArgs;
use crate::crypto::{detect_secret_type, target_plaintext_name};
use crate::error::EnstowError;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use std::path::{Path, PathBuf};
use tracing::info;
use walkdir::WalkDir;

#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub enum FileAction {
    Symlink { source: PathBuf, target: PathBuf },
    Decrypt { source: PathBuf, target: PathBuf },
}

impl FileAction {
    pub fn source(&self) -> &Path {
        match self {
            FileAction::Symlink { source, .. } => source,
            FileAction::Decrypt { source, .. } => source,
        }
    }

    pub fn target(&self) -> &Path {
        match self {
            FileAction::Symlink { target, .. } => target,
            FileAction::Decrypt { target, .. } => target,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryStatus {
    Synced,
    Missing,
    Conflict,
    #[serde(alias = "drift")]
    Modified,
    Unverified,
}

#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize)]
pub struct FileActionStatus {
    pub action: FileAction,
    pub status: EntryStatus,
}

pub fn check_status(
    actions: &[FileAction],
    age_key_file: Option<&Path>,
) -> Result<Vec<FileActionStatus>, EnstowError> {
    let mut statuses = Vec::new();

    for action in actions {
        if find_folded_ancestor(action.source(), action.target(), None).is_some() {
            statuses.push(FileActionStatus {
                action: action.clone(),
                status: EntryStatus::Conflict,
            });
            continue;
        }

        let status = match action {
            FileAction::Symlink { source, target } => {
                if is_symlink_to(target, source) {
                    EntryStatus::Synced
                } else if target.exists() || std::fs::symlink_metadata(target).is_ok() {
                    EntryStatus::Conflict
                } else {
                    EntryStatus::Missing
                }
            }
            FileAction::Decrypt { source, target } => {
                if let Ok(meta) = std::fs::symlink_metadata(target) {
                    if meta.file_type().is_symlink() || meta.is_dir() {
                        EntryStatus::Conflict
                    } else {
                        let secret_type = detect_secret_type(source).ok_or_else(|| {
                            EnstowError::Config(format!(
                                "Unrecognized secret format: {}",
                                source.display()
                            ))
                        })?;
                        match crate::crypto::decrypt_to_memory(source, secret_type, age_key_file) {
                            Ok(decrypted) => match std::fs::read(target) {
                                Ok(existing) => {
                                    if existing == decrypted {
                                        EntryStatus::Synced
                                    } else {
                                        EntryStatus::Modified
                                    }
                                }
                                Err(_) => EntryStatus::Conflict,
                            },
                            Err(_) => EntryStatus::Unverified,
                        }
                    }
                } else {
                    EntryStatus::Missing
                }
            }
        };

        statuses.push(FileActionStatus {
            action: action.clone(),
            status,
        });
    }

    Ok(statuses)
}

pub fn plan_stow(args: &CommonArgs) -> Result<Vec<FileAction>, EnstowError> {
    let source_path = args.source_path();
    let target_path = args.target_path();
    let source_root = normalize_path(&source_path.canonicalize().map_err(|e| EnstowError::Io {
        path: source_path.to_path_buf(),
        source: e,
    })?);

    let pkg_roots = if args.packages.is_empty() {
        vec![source_root.clone()]
    } else {
        let mut roots = Vec::new();
        for pkg in &args.packages {
            let pkg_path = source_root.join(pkg);
            let canonical =
                normalize_path(&pkg_path.canonicalize().map_err(|e| EnstowError::Io {
                    path: pkg_path.clone(),
                    source: e,
                })?);
            if !canonical.is_dir() {
                return Err(EnstowError::Config(format!(
                    "Package '{}' is not a directory: {}",
                    pkg,
                    pkg_path.display()
                )));
            }
            roots.push(canonical);
        }
        roots
    };

    let mut actions = Vec::new();

    for pkg_root in pkg_roots {
        let gitignore = build_gitignore(&pkg_root, &source_root, &args.ignore);

        for entry in WalkDir::new(&pkg_root)
            .min_depth(1)
            .into_iter()
            .filter_entry(|e| {
                !gitignore
                    .matched_path_or_any_parents(e.path(), e.file_type().is_dir())
                    .is_ignore()
            })
        {
            let entry = entry.map_err(|e| EnstowError::Io {
                path: e.path().unwrap_or(&pkg_root).to_path_buf(),
                source: std::io::Error::other(e.to_string()),
            })?;

            let path = entry.path();
            if path.is_dir() {
                continue;
            }

            let rel_path = path.strip_prefix(&pkg_root).map_err(|_| {
                EnstowError::Config(format!(
                    "Failed to compute relative path for {}",
                    path.display()
                ))
            })?;

            if let Some(_secret_type) = detect_secret_type(path) {
                let file_name = target_plaintext_name(path).unwrap_or_else(|| {
                    rel_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                });

                let target_rel = if let Some(parent) = rel_path.parent() {
                    parent.join(file_name)
                } else {
                    PathBuf::from(file_name)
                };

                actions.push(FileAction::Decrypt {
                    source: path.to_path_buf(),
                    target: target_path.join(target_rel),
                });
            } else {
                actions.push(FileAction::Symlink {
                    source: path.to_path_buf(),
                    target: target_path.join(rel_path),
                });
            }
        }
    }

    Ok(actions)
}

pub fn plan_unstow(args: &CommonArgs) -> Result<Vec<FileAction>, EnstowError> {
    let mut actions = plan_stow(args)?;
    let stale_links = plan_prune(args)?;
    actions.extend(stale_links);
    Ok(actions)
}

/// Find all age encrypted secret files across the specified packages or the source root.
pub fn find_age_secrets(
    source_root: &Path,
    packages: &[String],
    ignore: &[String],
) -> Result<Vec<PathBuf>, EnstowError> {
    let source_canonical =
        normalize_path(&source_root.canonicalize().map_err(|e| EnstowError::Io {
            path: source_root.to_path_buf(),
            source: e,
        })?);

    let mut roots = Vec::new();
    let mut individual_files = Vec::new();

    if packages.is_empty() {
        roots.push(source_canonical.clone());
    } else {
        for pkg in packages {
            let pkg_path = source_canonical.join(pkg);
            let canonical =
                normalize_path(&pkg_path.canonicalize().map_err(|e| EnstowError::Io {
                    path: pkg_path.clone(),
                    source: e,
                })?);
            if canonical.is_dir() {
                roots.push(canonical);
            } else if canonical.is_file() {
                if detect_secret_type(&canonical) == Some(crate::crypto::SecretType::Age) {
                    individual_files.push(canonical);
                }
            } else {
                return Err(EnstowError::Config(format!(
                    "Package '{}' is not a directory or file: {}",
                    pkg,
                    pkg_path.display()
                )));
            }
        }
    }

    let mut age_files = individual_files;

    for pkg_root in roots {
        let gitignore = build_gitignore(&pkg_root, &source_canonical, ignore);

        for entry in WalkDir::new(&pkg_root)
            .min_depth(1)
            .into_iter()
            .filter_entry(|e| {
                !gitignore
                    .matched_path_or_any_parents(e.path(), e.file_type().is_dir())
                    .is_ignore()
            })
        {
            let entry = entry.map_err(|e| EnstowError::Io {
                path: e.path().unwrap_or(&pkg_root).to_path_buf(),
                source: std::io::Error::other(e.to_string()),
            })?;

            let path = entry.path();
            if !path.is_dir() && detect_secret_type(path) == Some(crate::crypto::SecretType::Age) {
                age_files.push(path.to_path_buf());
            }
        }
    }

    age_files.sort();
    age_files.dedup();
    Ok(age_files)
}

/// Plan removal of stale symlinks belonging to managed packages that are no longer active dotfiles.
pub fn plan_prune(args: &CommonArgs) -> Result<Vec<FileAction>, EnstowError> {
    let active_actions = plan_stow(args)?;

    let source_path = args.source_path();
    let target_path = args.target_path();
    let source_root = source_path.canonicalize().map_err(|e| EnstowError::Io {
        path: source_path.to_path_buf(),
        source: e,
    })?;

    let pkg_roots = if args.packages.is_empty() {
        if args.ignore.iter().any(|p| p == "*") {
            Vec::new()
        } else {
            vec![source_root]
        }
    } else {
        let mut roots = Vec::new();
        for pkg in &args.packages {
            let pkg_path = source_root.join(pkg);
            let canonical = pkg_path.canonicalize().map_err(|e| EnstowError::Io {
                path: pkg_path.clone(),
                source: e,
            })?;
            roots.push(canonical);
        }
        roots
    };

    let target_canonical = target_path
        .canonicalize()
        .unwrap_or_else(|_| target_path.clone());

    let mut stale_actions = Vec::new();

    if target_canonical.is_dir() {
        for entry in WalkDir::new(&target_canonical)
            .max_depth(5)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_str().unwrap_or_default();
                if e.file_type().is_dir() {
                    !is_stale_scan_ignored_dir(name)
                } else {
                    true
                }
            })
        {
            let Ok(entry) = entry else {
                continue;
            };

            if entry.path_is_symlink() {
                let symlink_path = entry.path();
                if let Ok(dest) = std::fs::read_link(symlink_path) {
                    let full_dest = if dest.is_relative() {
                        match symlink_path.parent() {
                            Some(parent) => parent.join(&dest),
                            None => dest,
                        }
                    } else {
                        dest
                    };

                    let norm_dest = normalize_path(&full_dest);
                    let canon_dest = full_dest.canonicalize().ok().or_else(|| {
                        // For dangling symlinks where target was removed, resolve nearest existing ancestor
                        let mut ancestor = full_dest.parent();
                        let mut rel_components = Vec::new();
                        if let Some(name) = full_dest.file_name() {
                            rel_components.push(name);
                        }
                        while let Some(dir) = ancestor {
                            if let Ok(canon) = dir.canonicalize() {
                                let mut res = canon;
                                for comp in rel_components.into_iter().rev() {
                                    res.push(comp);
                                }
                                return Some(res);
                            }
                            if let Some(name) = dir.file_name() {
                                rel_components.push(name);
                            }
                            ancestor = dir.parent();
                        }
                        None
                    });
                    let norm_canon_dest = canon_dest.as_ref().map(|c| normalize_path(c));

                    let belongs_to_pkg = pkg_roots.iter().any(|pkg_root| {
                        let norm_pkg = normalize_path(pkg_root);
                        norm_dest.starts_with(&norm_pkg)
                            || norm_canon_dest
                                .as_ref()
                                .map(|c| c.starts_with(&norm_pkg))
                                .unwrap_or(false)
                    });

                    if belongs_to_pkg {
                        let already_active = active_actions.iter().any(|a| {
                            let t = a.target();
                            t == symlink_path
                                || normalize_path(t) == normalize_path(symlink_path)
                                || t.canonicalize().ok().map(|c| normalize_path(&c))
                                    == symlink_path.canonicalize().ok().map(|c| normalize_path(&c))
                        });

                        if !already_active {
                            let norm_sp = normalize_path(symlink_path);
                            let norm_tc = normalize_path(&target_canonical);
                            let relative_target = symlink_path
                                .strip_prefix(&target_canonical)
                                .or_else(|_| norm_sp.strip_prefix(&norm_tc));
                            let target = match relative_target {
                                Ok(rel) => target_path.join(rel),
                                Err(_) => symlink_path.to_path_buf(),
                            };

                            stale_actions.push(FileAction::Symlink {
                                source: full_dest,
                                target,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(stale_actions)
}

pub(crate) fn is_stale_scan_ignored_dir(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".cargo"
            | ".rustup"
            | ".cache"
            | "node_modules"
            | "target"
            | ".npm"
            | ".gradle"
            | ".gemini"
            | ".pub-cache"
            | ".platformio"
            | ".password-store"
            | ".password-store-backup"
            | ".enstow-backup"
            | ".gvm"
            | ".bun"
            | ".tesseract-rs"
            | ".serena"
            | ".codegraph"
            | ".agents"
            | ".github"
            | "git"
            | "go"
    )
}

pub fn execute_plan(
    actions: &[FileAction],
    dry_run: bool,
    age_key_file: Option<&Path>,
    force: bool,
) -> Result<(), EnstowError> {
    execute_plan_with_backup(actions, dry_run, age_key_file, force, false, None, None)
}

pub fn execute_plan_with_backup(
    actions: &[FileAction],
    dry_run: bool,
    age_key_file: Option<&Path>,
    force: bool,
    backup: bool,
    backup_dir: Option<&Path>,
    target_root: Option<&Path>,
) -> Result<(), EnstowError> {
    execute_plan_with_backup_and_permissions(
        actions,
        dry_run,
        age_key_file,
        force,
        backup,
        backup_dir,
        target_root,
        None,
        false,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictResolution {
    Overwrite,
    Adopt,
    Skip,
}

pub fn prompt_conflict_resolution<R: std::io::BufRead, W: std::io::Write>(
    action: &FileAction,
    age_key_file: Option<&Path>,
    reader: &mut R,
    writer: &mut W,
    colorize: bool,
) -> Result<ConflictResolution, EnstowError> {
    loop {
        write!(
            writer,
            "Conflict detected for {}: [d]iff, [o]verwrite, [a]dopt, [s]kip: ",
            action.target().display()
        )
        .map_err(|e| EnstowError::Io {
            path: action.target().to_path_buf(),
            source: e,
        })?;
        writer.flush().map_err(|e| EnstowError::Io {
            path: action.target().to_path_buf(),
            source: e,
        })?;

        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line).map_err(|e| EnstowError::Io {
            path: action.target().to_path_buf(),
            source: e,
        })?;
        if bytes_read == 0 {
            return Ok(ConflictResolution::Skip);
        }

        match line.trim().to_ascii_lowercase().as_str() {
            "d" | "diff" => {
                let diffs =
                    crate::diff::compute_diff(std::slice::from_ref(action), age_key_file, false)?;
                for file_diff in &diffs {
                    let text = if colorize {
                        crate::diff::colorize_diff(&file_diff.diff)
                    } else {
                        file_diff.diff.clone()
                    };
                    write!(writer, "{text}").map_err(|e| EnstowError::Io {
                        path: action.target().to_path_buf(),
                        source: e,
                    })?;
                }
            }
            "o" | "overwrite" => return Ok(ConflictResolution::Overwrite),
            "a" | "adopt" => return Ok(ConflictResolution::Adopt),
            "s" | "skip" => return Ok(ConflictResolution::Skip),
            _ => {
                writeln!(
                    writer,
                    "Invalid choice. Please enter 'd' (diff), 'o' (overwrite), 'a' (adopt), or 's' (skip)."
                )
                .map_err(|e| EnstowError::Io {
                    path: action.target().to_path_buf(),
                    source: e,
                })?;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn execute_plan_with_backup_and_permissions(
    actions: &[FileAction],
    dry_run: bool,
    age_key_file: Option<&Path>,
    force: bool,
    backup: bool,
    backup_dir: Option<&Path>,
    target_root: Option<&Path>,
    permissions: Option<&crate::config::PermissionsConfig>,
    adopt: bool,
) -> Result<(), EnstowError> {
    execute_plan_interactive(
        actions,
        dry_run,
        age_key_file,
        &[],
        force,
        backup,
        backup_dir,
        target_root,
        permissions,
        adopt,
        false,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn execute_plan_interactive(
    actions: &[FileAction],
    dry_run: bool,
    age_key_file: Option<&Path>,
    recipients: &[String],
    force: bool,
    backup: bool,
    backup_dir: Option<&Path>,
    target_root: Option<&Path>,
    permissions: Option<&crate::config::PermissionsConfig>,
    adopt: bool,
    interactive: bool,
) -> Result<(), EnstowError> {
    use std::io::IsTerminal;
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let mut writer = std::io::stderr();
    let colorize = std::io::stderr().is_terminal() && std::env::var("NO_COLOR").is_err();
    execute_plan_interactive_with_io(
        actions,
        dry_run,
        age_key_file,
        recipients,
        force,
        backup,
        backup_dir,
        target_root,
        permissions,
        adopt,
        interactive,
        &mut reader,
        &mut writer,
        colorize,
    )
}

fn target_mode_matches(meta: &std::fs::Metadata, expected_mode: u32) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o7777) == (expected_mode & 0o7777)
    }
    #[cfg(not(unix))]
    {
        let _ = (meta, expected_mode);
        true
    }
}

fn heal_target_mode(target: &Path, expected_mode: u32) -> Result<(), EnstowError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(expected_mode)).map_err(
            |e| EnstowError::Io {
                path: target.to_path_buf(),
                source: e,
            },
        )?;
    }
    #[cfg(not(unix))]
    {
        let _ = (target, expected_mode);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn execute_plan_interactive_with_io<R: std::io::BufRead, W: std::io::Write>(
    actions: &[FileAction],
    dry_run: bool,
    age_key_file: Option<&Path>,
    recipients: &[String],
    force: bool,
    backup: bool,
    backup_dir: Option<&Path>,
    target_root: Option<&Path>,
    permissions: Option<&crate::config::PermissionsConfig>,
    adopt: bool,
    interactive: bool,
    reader: &mut R,
    writer: &mut W,
    colorize: bool,
) -> Result<(), EnstowError> {
    let mut unfolded_dry_run = std::collections::HashSet::new();
    let resolved_backup_dir = if backup {
        backup_dir.map(|bd| {
            resolve_backup_dir_for_run(bd, &format_backup_timestamp(std::time::SystemTime::now()))
        })
    } else {
        None
    };
    let mut backed_up_count: usize = 0;

    let result: Result<(), EnstowError> = (|| {
        for action in actions {
            match action {
                FileAction::Symlink { source, target } => {
                    let had_folded = unfold_folded_ancestors(
                        source,
                        target,
                        target_root,
                        dry_run,
                        &mut unfolded_dry_run,
                    )?;
                    if dry_run && had_folded {
                        println!(
                            "[dry-run] LINK  {} -> {}",
                            target.display(),
                            source.display()
                        );
                        continue;
                    }

                    if is_symlink_to(target, source) {
                        continue;
                    }

                    ensure_target_not_inside_source(source, target, target_root)?;

                    let mut file_force = force;
                    let mut file_adopt = adopt;

                    if let Ok(meta) = std::fs::symlink_metadata(target) {
                        if !file_force && !backup && !file_adopt {
                            if interactive {
                                match prompt_conflict_resolution(
                                    action,
                                    age_key_file,
                                    reader,
                                    writer,
                                    colorize,
                                )? {
                                    ConflictResolution::Overwrite => file_force = true,
                                    ConflictResolution::Adopt => file_adopt = true,
                                    ConflictResolution::Skip => continue,
                                }
                            } else {
                                return Err(EnstowError::Collision {
                                    path: target.to_path_buf(),
                                });
                            }
                        }

                        if file_adopt {
                            if dry_run {
                                println!(
                                    "[dry-run] ADOPT {} -> {}",
                                    target.display(),
                                    source.display()
                                );
                                println!(
                                    "[dry-run] LINK  {} -> {}",
                                    target.display(),
                                    source.display()
                                );
                                continue;
                            }

                            if let Some(parent) = source.parent() {
                                std::fs::create_dir_all(parent).map_err(|e| EnstowError::Io {
                                    path: parent.to_path_buf(),
                                    source: e,
                                })?;
                            }
                            std::fs::copy(target, source).map_err(|e| EnstowError::Io {
                                path: source.to_path_buf(),
                                source: e,
                            })?;
                            #[cfg(unix)]
                            {
                                let _ = std::fs::set_permissions(source, meta.permissions());
                            }
                            remove_target(target, &meta)?;
                            create_symlink(source, target, true)?;
                            continue;
                        }

                        let backup_dest = resolved_backup_dir
                            .as_deref()
                            .map(|bd| compute_backup_dest(target, bd, target_root));

                        if dry_run {
                            if backup {
                                if let Some(dest) = &backup_dest {
                                    println!(
                                        "[dry-run] BACKUP {} -> {}",
                                        target.display(),
                                        dest.display()
                                    );
                                }
                            }
                            println!(
                                "[dry-run] LINK  {} -> {}",
                                target.display(),
                                source.display()
                            );
                            continue;
                        }

                        if backup {
                            if let Some(dest) = &backup_dest {
                                backup_file(target, dest)?;
                                backed_up_count += 1;
                            }
                        } else if file_force {
                            remove_target(target, &meta)?;
                        }
                    } else if dry_run {
                        println!(
                            "[dry-run] LINK  {} -> {}",
                            target.display(),
                            source.display()
                        );
                        continue;
                    }

                    create_symlink(source, target, file_force)?;
                }
                FileAction::Decrypt { source, target } => {
                    let mode = permissions
                        .map(|p| p.resolve_mode(target, Some(source), target_root))
                        .unwrap_or(0o600);
                    let had_folded = unfold_folded_ancestors(
                        source,
                        target,
                        target_root,
                        dry_run,
                        &mut unfolded_dry_run,
                    )?;
                    if dry_run && had_folded {
                        println!(
                            "[dry-run] DECRYPT {} -> {} (mode {:04o})",
                            source.display(),
                            target.display(),
                            mode
                        );
                        continue;
                    }

                    ensure_target_not_inside_source(source, target, target_root)?;

                    let mut file_force = force;
                    let mut file_adopt = adopt;
                    let mut predecrypted = None;

                    if let Ok(meta) = std::fs::symlink_metadata(target) {
                        if !meta.file_type().is_symlink() && !meta.is_dir() {
                            if let Some(secret_type) = detect_secret_type(source) {
                                if let (Ok(decrypted), Ok(existing)) = (
                                    crate::crypto::decrypt_to_memory(
                                        source,
                                        secret_type,
                                        age_key_file,
                                    ),
                                    std::fs::read(target),
                                ) {
                                    if existing == decrypted {
                                        if !target_mode_matches(&meta, mode) {
                                            if dry_run {
                                                println!(
                                                    "[dry-run] CHMOD {} (mode {:04o})",
                                                    target.display(),
                                                    mode
                                                );
                                            } else {
                                                heal_target_mode(target, mode)?;
                                            }
                                        }
                                        continue;
                                    }
                                    predecrypted = Some(decrypted);
                                }
                            }
                        }

                        if !file_force && !backup && !file_adopt {
                            if interactive {
                                match prompt_conflict_resolution(
                                    action,
                                    age_key_file,
                                    reader,
                                    writer,
                                    colorize,
                                )? {
                                    ConflictResolution::Overwrite => file_force = true,
                                    ConflictResolution::Adopt => file_adopt = true,
                                    ConflictResolution::Skip => continue,
                                }
                            } else {
                                return Err(EnstowError::Collision {
                                    path: target.to_path_buf(),
                                });
                            }
                        }

                        if file_adopt {
                            if dry_run {
                                println!(
                                    "[dry-run] ADOPT {} -> {}",
                                    target.display(),
                                    source.display()
                                );
                                println!(
                                    "[dry-run] DECRYPT {} -> {} (mode {:04o})",
                                    source.display(),
                                    target.display(),
                                    mode
                                );
                                continue;
                            }

                            let plaintext = std::fs::read(target).map_err(|e| EnstowError::Io {
                                path: target.to_path_buf(),
                                source: e,
                            })?;
                            let resolved_recipients =
                                crate::crypto::resolve_age_recipients(recipients, age_key_file)?;
                            crate::crypto::encrypt_bytes_age_with_recipients(
                                &plaintext,
                                source,
                                &resolved_recipients,
                            )?;
                            crate::crypto::write_secure_file_with_mode(
                                target, &plaintext, true, mode,
                            )?;
                            continue;
                        }

                        let backup_dest = resolved_backup_dir
                            .as_deref()
                            .map(|bd| compute_backup_dest(target, bd, target_root));

                        if dry_run {
                            if backup {
                                if let Some(dest) = &backup_dest {
                                    println!(
                                        "[dry-run] BACKUP {} -> {}",
                                        target.display(),
                                        dest.display()
                                    );
                                }
                            }
                            println!(
                                "[dry-run] DECRYPT {} -> {} (mode {:04o})",
                                source.display(),
                                target.display(),
                                mode
                            );
                            continue;
                        }

                        if backup {
                            if let Some(dest) = &backup_dest {
                                backup_file(target, dest)?;
                                backed_up_count += 1;
                            }
                        } else if file_force {
                            remove_target(target, &meta)?;
                        }
                    } else if dry_run {
                        println!(
                            "[dry-run] DECRYPT {} -> {} (mode {:04o})",
                            source.display(),
                            target.display(),
                            mode
                        );
                        continue;
                    }

                    info!("Decrypting {} -> {}", source.display(), target.display());
                    let plaintext = match predecrypted {
                        Some(bytes) => bytes,
                        None => {
                            let secret_type = detect_secret_type(source).ok_or_else(|| {
                                EnstowError::Config(format!(
                                    "Unrecognized secret format: {}",
                                    source.display()
                                ))
                            })?;
                            crate::crypto::decrypt_to_memory(source, secret_type, age_key_file)?
                        }
                    };
                    crate::crypto::write_secure_file_with_mode(
                        target, &plaintext, file_force, mode,
                    )?;
                }
            }
        }
        Ok(())
    })();

    if !dry_run && backed_up_count > 0 {
        if let Some(dir) = &resolved_backup_dir {
            let noun = if backed_up_count == 1 {
                "file"
            } else {
                "files"
            };
            println!("Backed up {backed_up_count} {noun} to {}", dir.display());
        }
    }

    result
}

/// Overwrite regular file content with zeros and flush to disk.
pub fn zeroize_file(path: &Path) -> Result<(), EnstowError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| EnstowError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    if metadata.file_type().is_symlink() {
        return Ok(());
    }

    if metadata.is_file() {
        let len = metadata.len();
        if len > 0 {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = metadata.permissions();
                if perms.mode() & 0o200 == 0 {
                    perms.set_mode(perms.mode() | 0o200);
                    let _ = std::fs::set_permissions(path, perms);
                }
            }
            #[cfg(windows)]
            {
                let mut perms = metadata.permissions();
                if perms.readonly() {
                    perms.set_readonly(false);
                    let _ = std::fs::set_permissions(path, perms);
                }
            }

            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(path)
                .map_err(|e| EnstowError::Io {
                    path: path.to_path_buf(),
                    source: e,
                })?;

            use std::io::Write;
            const CHUNK_SIZE: usize = 8192;
            const ZEROS: [u8; CHUNK_SIZE] = [0u8; CHUNK_SIZE];
            let mut remaining = len;
            while remaining > 0 {
                let write_size = std::cmp::min(remaining, CHUNK_SIZE as u64) as usize;
                file.write_all(&ZEROS[..write_size])
                    .map_err(|e| EnstowError::Io {
                        path: path.to_path_buf(),
                        source: e,
                    })?;
                remaining -= write_size as u64;
            }

            file.sync_all().map_err(|e| EnstowError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;
        }
    }

    Ok(())
}

/// Securely zeroize and delete a file.
pub fn shred_file(path: &Path) -> Result<(), EnstowError> {
    let _ = zeroize_file(path);
    std::fs::remove_file(path).map_err(|e| EnstowError::Io {
        path: path.to_path_buf(),
        source: e,
    })
}

pub fn execute_unstow_plan(
    actions: &[FileAction],
    target_root: &Path,
    dry_run: bool,
) -> Result<(), EnstowError> {
    execute_unstow_plan_with_shred(actions, target_root, dry_run, false)
}

pub fn execute_unstow_plan_with_shred(
    actions: &[FileAction],
    target_root: &Path,
    dry_run: bool,
    shred: bool,
) -> Result<(), EnstowError> {
    let target_canonical = target_root
        .canonicalize()
        .unwrap_or_else(|_| target_root.to_path_buf());
    for action in actions {
        match action {
            FileAction::Symlink { source, target } => {
                if is_symlink_to(target, source) {
                    if dry_run {
                        println!("[dry-run] UNLINK {}", target.display());
                    } else {
                        info!("Unlinking {}", target.display());
                        unlink_symlink(target)?;
                        clean_empty_parents(target, &target_canonical);
                    }
                }
            }
            FileAction::Decrypt { source, target } => {
                if find_folded_ancestor(source, target, Some(target_root)).is_some() {
                    continue;
                }
                if target.exists() || std::fs::symlink_metadata(target).is_ok() {
                    if dry_run {
                        if shred {
                            println!("[dry-run] SHRED SECRET {}", target.display());
                        } else {
                            println!("[dry-run] REMOVE SECRET {}", target.display());
                        }
                    } else {
                        if shred {
                            info!("Shredding secret {}", target.display());
                            shred_file(target)?;
                        } else {
                            info!("Removing secret {}", target.display());
                            std::fs::remove_file(target).map_err(|e| EnstowError::Io {
                                path: target.to_path_buf(),
                                source: e,
                            })?;
                        }
                        clean_empty_parents(target, &target_canonical);
                    }
                }
            }
        }
    }
    Ok(())
}

fn clean_empty_parents(path: &Path, stop_at: &Path) {
    let norm_stop = normalize_path(stop_at);
    let mut current = path.parent();
    while let Some(dir) = current {
        if normalize_path(dir) == norm_stop {
            break;
        }
        if let Ok(c) = dir.canonicalize() {
            if normalize_path(&c) == norm_stop {
                break;
            }
        }
        // Try removing dir; if not empty, rmdir fails and we stop
        if std::fs::remove_dir(dir).is_err() {
            break;
        }
        current = dir.parent();
    }
}

const DEFAULT_IGNORES: &[&str] = &[
    ".git",
    ".gitignore",
    ".codegraph",
    ".serena",
    ".agents",
    ".github",
    "target",
    "Cargo.lock",
    ".enstowignore",
    ".stow-local-ignore",
    ".secrets.age",
    ".secrets.*.age",
    ".enstow-secrets*",
    "enstow.toml",
    "enstow.yaml",
    "enstow.yml",
    "enstow.json",
    ".enstow.toml",
    ".enstow.yaml",
    ".enstow.yml",
    ".enstow.json",
];

fn build_gitignore(pkg_root: &Path, source_root: &Path, extra_patterns: &[String]) -> Gitignore {
    let mut builder = GitignoreBuilder::new(pkg_root);

    // Default ignored files and directories across dotfile repositories
    for pat in DEFAULT_IGNORES {
        let _ = builder.add_line(None, pat);
    }

    // Global ignore files at source root if different from package root
    if pkg_root != source_root {
        for candidate in [".stow-local-ignore", ".enstowignore"] {
            let path = source_root.join(candidate);
            if path.is_file() {
                builder.add(path);
            }
        }
    }

    // Package-level ignore files (.enstowignore and fallback .stow-local-ignore)
    for candidate in [".stow-local-ignore", ".enstowignore"] {
        let path = pkg_root.join(candidate);
        if path.is_file() {
            builder.add(path);
        }
    }

    // CLI --ignore args, ENSTOW_IGNORE env, and config file ignore patterns
    for pat in extra_patterns {
        let _ = builder.add_line(None, pat.trim());
    }

    builder.build().unwrap_or_else(|_| Gitignore::empty())
}

fn strip_verbatim_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{}", stripped))
    } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else if let Some(stripped) = s.strip_prefix(r"\??\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

pub fn normalize_path(path: &Path) -> PathBuf {
    use std::path::Component;
    let stripped = strip_verbatim_prefix(path);
    let mut out = PathBuf::new();
    for comp in stripped.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            c => out.push(c.as_os_str()),
        }
    }
    out
}

pub fn is_symlink_to(target: &Path, expected_source: &Path) -> bool {
    if let Ok(meta) = std::fs::symlink_metadata(target) {
        if meta.file_type().is_symlink() {
            if let Ok(dest) = std::fs::read_link(target) {
                if dest == expected_source {
                    return true;
                }
                let full_dest = if dest.is_relative() {
                    match target.parent() {
                        Some(parent) => parent.join(&dest),
                        None => dest,
                    }
                } else {
                    dest
                };
                if full_dest == expected_source {
                    return true;
                }
                if normalize_path(&full_dest) == normalize_path(expected_source) {
                    return true;
                }
                if let (Ok(c1), Ok(c2)) = (full_dest.canonicalize(), expected_source.canonicalize())
                {
                    return normalize_path(&c1) == normalize_path(&c2);
                }
            }
        }
    }
    false
}

/// Inspect ancestor directories of `target` (between `target_root` and `target`, exclusive)
/// and return the shallowest symlink pointing into `source`'s directory hierarchy
/// (e.g. a legacy GNU Stow folded directory symlink).
pub fn find_folded_ancestor(
    source: &Path,
    target: &Path,
    target_root: Option<&Path>,
) -> Option<(PathBuf, PathBuf)> {
    let norm_raw_source = normalize_path(source);
    let norm_source = normalize_path(
        &source
            .canonicalize()
            .unwrap_or_else(|_| source.to_path_buf()),
    );

    let mut ancestors = Vec::new();
    if let Some(root) = target_root {
        let norm_root = normalize_path(root);
        let canon_root = root.canonicalize().ok().map(|c| normalize_path(&c));
        let mut cur = target.parent();
        let mut reached_root = false;
        while let Some(dir) = cur {
            let norm_dir = normalize_path(dir);
            if dir == root || norm_dir == norm_root {
                reached_root = true;
                break;
            }
            if let Some(ref cr) = canon_root {
                if dir.canonicalize().ok().map(|c| normalize_path(&c)).as_ref() == Some(cr) {
                    reached_root = true;
                    break;
                }
            }
            ancestors.push(dir.to_path_buf());
            cur = dir.parent();
        }
        if !reached_root {
            ancestors.clear();
        }
    } else {
        let mut cur = target.parent();
        let mut src_cur = source.parent();
        while let (Some(dir), Some(sdir)) = (cur, src_cur) {
            let Some(dir_name) = dir.file_name() else {
                break;
            };
            if sdir.file_name() != Some(dir_name) {
                break;
            }
            let norm_dir = normalize_path(dir);
            if norm_dir == normalize_path(sdir)
                || (norm_dir.is_absolute()
                    && norm_dir.parent().and_then(|p| p.file_name()).is_none())
            {
                break;
            }
            ancestors.push(dir.to_path_buf());
            cur = dir.parent();
            src_cur = sdir.parent();
        }
    }

    ancestors.reverse();
    for anc in ancestors {
        if norm_raw_source.starts_with(normalize_path(&anc)) {
            continue;
        }
        if let Ok(meta) = std::fs::symlink_metadata(&anc) {
            if meta.file_type().is_symlink() {
                if let Ok(dest) = std::fs::read_link(&anc) {
                    let full_dest = if dest.is_relative() {
                        match anc.parent() {
                            Some(parent) => parent.join(&dest),
                            None => dest,
                        }
                    } else {
                        dest
                    };
                    let norm_dest = normalize_path(&full_dest.canonicalize().unwrap_or(full_dest));
                    if norm_dest != norm_source && norm_source.starts_with(&norm_dest) {
                        return Some((anc, norm_dest));
                    }
                }
            }
        }
    }

    None
}

fn unlink_symlink(path: &Path) -> Result<(), EnstowError> {
    #[cfg(unix)]
    {
        std::fs::remove_file(path).map_err(|e| EnstowError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    }
    #[cfg(windows)]
    {
        std::fs::remove_file(path)
            .or_else(|_| std::fs::remove_dir(path))
            .map_err(|e| EnstowError::Io {
                path: path.to_path_buf(),
                source: e,
            })
    }
}

fn unfold_folded_ancestors(
    source: &Path,
    target: &Path,
    target_root: Option<&Path>,
    dry_run: bool,
    unfolded_dry_run: &mut std::collections::HashSet<PathBuf>,
) -> Result<bool, EnstowError> {
    let mut found_any = false;
    while let Some((folded_dir, resolved_dest)) = find_folded_ancestor(source, target, target_root)
    {
        found_any = true;
        if dry_run {
            if unfolded_dry_run.insert(folded_dir.clone()) {
                println!(
                    "[dry-run] UNFOLD {} -> {}",
                    folded_dir.display(),
                    resolved_dest.display()
                );
            }
            break;
        }
        info!(
            "Unfolding legacy directory symlink {} -> {}",
            folded_dir.display(),
            resolved_dest.display()
        );
        unlink_symlink(&folded_dir)?;
        std::fs::create_dir_all(&folded_dir).map_err(|e| EnstowError::Io {
            path: folded_dir,
            source: e,
        })?;
    }
    Ok(found_any)
}

fn ensure_target_not_inside_source(
    source: &Path,
    target: &Path,
    target_root: Option<&Path>,
) -> Result<(), EnstowError> {
    if let Some((folded, dest)) = find_folded_ancestor(source, target, target_root) {
        return Err(EnstowError::Config(format!(
            "Refusing to modify '{}' through folded directory symlink '{}' -> '{}'",
            target.display(),
            folded.display(),
            dest.display()
        )));
    }
    let Some(source_parent) = source.parent() else {
        return Ok(());
    };
    let Some(target_parent) = target.parent() else {
        return Ok(());
    };
    if let (Ok(sp), Ok(tp)) = (source_parent.canonicalize(), target_parent.canonicalize()) {
        let norm_sp = normalize_path(&sp);
        let norm_tp = normalize_path(&tp);
        if norm_tp == norm_sp {
            let same_file =
                source.file_name().is_some() && source.file_name() == target.file_name();
            let secret_in_source_dir = detect_secret_type(source).is_some();
            if same_file || secret_in_source_dir {
                return Err(EnstowError::Config(format!(
                    "Refusing to modify '{}' because it resolves to source directory '{}'",
                    target.display(),
                    norm_sp.display()
                )));
            }
        }
    }
    Ok(())
}

fn remove_target(target: &Path, meta: &std::fs::Metadata) -> Result<(), EnstowError> {
    if meta.file_type().is_dir() {
        std::fs::remove_dir_all(target).map_err(|e| EnstowError::Io {
            path: target.to_path_buf(),
            source: e,
        })
    } else if meta.file_type().is_symlink() {
        unlink_symlink(target)
    } else {
        std::fs::remove_file(target).map_err(|e| EnstowError::Io {
            path: target.to_path_buf(),
            source: e,
        })
    }
}

/// Placeholder token expanded to a `YYYYMMDD_HHMMSS` UTC run timestamp in backup directory paths.
pub const BACKUP_TIMESTAMP_PLACEHOLDER: &str = "{timestamp}";

/// Format a `SystemTime` as a sortable `YYYYMMDD_HHMMSS` UTC timestamp without external crates.
pub fn format_backup_timestamp(time: std::time::SystemTime) -> String {
    let secs = time
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;

    // Howard Hinnant's civil-from-days algorithm (days since 1970-01-01)
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}{month:02}{day:02}_{hour:02}{minute:02}{second:02}")
}

fn expand_backup_timestamp(template: &Path, replacement: &str) -> Option<PathBuf> {
    let mut replaced = false;
    let mut out = PathBuf::new();
    for comp in template.components() {
        match comp {
            std::path::Component::Normal(os) => {
                if let Some(s) = os.to_str() {
                    if s.contains(BACKUP_TIMESTAMP_PLACEHOLDER) {
                        replaced = true;
                        out.push(s.replace(BACKUP_TIMESTAMP_PLACEHOLDER, replacement));
                        continue;
                    }
                }
                out.push(os);
            }
            other => out.push(other.as_os_str()),
        }
    }
    replaced.then_some(out)
}

/// Resolve the backup directory for a single run.
///
/// If `template` contains `{timestamp}`, it is replaced with `timestamp` (and disambiguated with
/// `_1`, `_2`, ... if that directory already exists on disk). Paths without `{timestamp}` are
/// returned unchanged.
pub fn resolve_backup_dir_for_run(template: &Path, timestamp: &str) -> PathBuf {
    let Some(candidate) = expand_backup_timestamp(template, timestamp) else {
        return template.to_path_buf();
    };
    if std::fs::symlink_metadata(&candidate).is_err() {
        return candidate;
    }
    for suffix in 1u64.. {
        let stamped = format!("{timestamp}_{suffix}");
        if let Some(next) = expand_backup_timestamp(template, &stamped) {
            if std::fs::symlink_metadata(&next).is_err() {
                return next;
            }
        }
    }
    candidate
}

fn compute_backup_dest(target: &Path, backup_dir: &Path, target_root: Option<&Path>) -> PathBuf {
    if let Some(root) = target_root {
        if let Ok(rel) = target.strip_prefix(root) {
            return backup_dir.join(rel);
        }
        let norm_target = normalize_path(target);
        let norm_root = normalize_path(root);
        if let Ok(rel) = norm_target.strip_prefix(&norm_root) {
            return backup_dir.join(rel);
        }
    }
    backup_dir.join(target.file_name().unwrap_or(target.as_os_str()))
}

fn backup_file(target: &Path, dest: &Path) -> Result<(), EnstowError> {
    info!(
        "Backing up collision {} -> {}",
        target.display(),
        dest.display()
    );

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| EnstowError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    if let Ok(meta) = std::fs::symlink_metadata(dest) {
        remove_target(dest, &meta)?;
    }

    if std::fs::rename(target, dest).is_err() {
        // Fallback when rename fails (e.g. cross-filesystem boundaries)
        let meta = std::fs::symlink_metadata(target).map_err(|e| EnstowError::Io {
            path: target.to_path_buf(),
            source: e,
        })?;

        if meta.file_type().is_symlink() {
            let link_dest = std::fs::read_link(target).map_err(|e| EnstowError::Io {
                path: target.to_path_buf(),
                source: e,
            })?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&link_dest, dest).map_err(|e| EnstowError::Io {
                path: dest.to_path_buf(),
                source: e,
            })?;
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(&link_dest, dest).map_err(|e| EnstowError::Io {
                path: dest.to_path_buf(),
                source: e,
            })?;
            std::fs::remove_file(target).map_err(|e| EnstowError::Io {
                path: target.to_path_buf(),
                source: e,
            })?;
        } else if meta.file_type().is_dir() {
            copy_dir_all(target, dest)?;
            std::fs::remove_dir_all(target).map_err(|e| EnstowError::Io {
                path: target.to_path_buf(),
                source: e,
            })?;
        } else {
            std::fs::copy(target, dest).map_err(|e| EnstowError::Io {
                path: target.to_path_buf(),
                source: e,
            })?;
            std::fs::remove_file(target).map_err(|e| EnstowError::Io {
                path: target.to_path_buf(),
                source: e,
            })?;
        }
    }

    Ok(())
}

fn copy_dir_all(src: &Path, dst: &Path) -> Result<(), EnstowError> {
    std::fs::create_dir_all(dst).map_err(|e| EnstowError::Io {
        path: dst.to_path_buf(),
        source: e,
    })?;
    for entry in WalkDir::new(src) {
        let entry = entry.map_err(|e| EnstowError::Io {
            path: src.to_path_buf(),
            source: e.into(),
        })?;
        let rel = entry
            .path()
            .strip_prefix(src)
            .map_err(|e| EnstowError::Io {
                path: entry.path().to_path_buf(),
                source: std::io::Error::other(e),
            })?;
        let target_dest = dst.join(rel);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target_dest).map_err(|e| EnstowError::Io {
                path: target_dest,
                source: e,
            })?;
        } else if entry.path_is_symlink() {
            let link = std::fs::read_link(entry.path()).map_err(|e| EnstowError::Io {
                path: entry.path().to_path_buf(),
                source: e,
            })?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&link, &target_dest).map_err(|e| EnstowError::Io {
                path: target_dest,
                source: e,
            })?;
            #[cfg(windows)]
            std::os::windows::fs::symlink_file(&link, &target_dest).map_err(|e| {
                EnstowError::Io {
                    path: target_dest,
                    source: e,
                }
            })?;
        } else {
            std::fs::copy(entry.path(), &target_dest).map_err(|e| EnstowError::Io {
                path: target_dest,
                source: e,
            })?;
        }
    }
    Ok(())
}

fn create_symlink(source: &Path, target: &Path, force: bool) -> Result<(), EnstowError> {
    if is_symlink_to(target, source) {
        // Already links to the same source
        return Ok(());
    }

    ensure_target_not_inside_source(source, target, None)?;

    if let Ok(meta) = std::fs::symlink_metadata(target) {
        if !force {
            return Err(EnstowError::Collision {
                path: target.to_path_buf(),
            });
        }

        // Force overwrite: remove existing file, symlink, or directory
        remove_target(target, &meta)?;
    }

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| EnstowError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    info!("Linking {} -> {}", target.display(), source.display());

    #[cfg(unix)]
    std::os::unix::fs::symlink(source, target).map_err(|e| EnstowError::Io {
        path: target.to_path_buf(),
        source: e,
    })?;

    #[cfg(windows)]
    std::os::windows::fs::symlink_file(source, target).map_err(|e| EnstowError::Io {
        path: target.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Resolve the deployed target path for an encrypted source file inside `source_root`.
pub fn resolve_secret_target(
    file: &Path,
    source_root: &Path,
    target_root: &Path,
    packages: &[String],
) -> Result<PathBuf, EnstowError> {
    let canon_file = normalize_path(&file.canonicalize().map_err(|e| EnstowError::Io {
        path: file.to_path_buf(),
        source: e,
    })?);
    let canon_source =
        normalize_path(&source_root.canonicalize().map_err(|e| EnstowError::Io {
            path: source_root.to_path_buf(),
            source: e,
        })?);
    let plain_name = target_plaintext_name(&canon_file).ok_or_else(|| {
        EnstowError::Config(format!(
            "Could not determine target filename for '{}'",
            file.display()
        ))
    })?;

    let rel_path = if packages.is_empty() {
        canon_file
            .strip_prefix(&canon_source)
            .ok()
            .map(Path::to_path_buf)
    } else {
        packages.iter().find_map(|pkg| {
            let pkg_root = canon_source.join(pkg);
            let canon_pkg = normalize_path(&pkg_root.canonicalize().unwrap_or(pkg_root));
            canon_file
                .strip_prefix(&canon_pkg)
                .ok()
                .map(Path::to_path_buf)
        })
    };

    let rel = rel_path.ok_or_else(|| {
        EnstowError::Config(format!(
            "Cannot resolve target path for '--apply': '{}' is not inside source directory '{}' (packages: {:?})",
            file.display(),
            source_root.display(),
            packages
        ))
    })?;

    Ok(target_root.join(rel.with_file_name(plain_name)))
}

/// Securely deploy updated plaintext for an edited secret to its resolved target path,
/// unfolding legacy directory symlinks and enforcing configured permissions (default `0600`).
pub fn deploy_edited_secret(
    source: &Path,
    target: &Path,
    target_root: &Path,
    plaintext: &[u8],
    permissions: Option<&crate::config::PermissionsConfig>,
) -> Result<u32, EnstowError> {
    let mut dry_seen = std::collections::HashSet::new();
    unfold_folded_ancestors(source, target, Some(target_root), false, &mut dry_seen)?;
    ensure_target_not_inside_source(source, target, Some(target_root))?;

    let mode = permissions
        .map(|p| p.resolve_mode(target, Some(source), Some(target_root)))
        .unwrap_or(0o600);
    crate::crypto::write_secure_file_with_mode(target, plaintext, true, mode)?;
    Ok(mode)
}

#[allow(clippy::too_many_arguments)]
pub fn add_file(
    file: &Path,
    package: &str,
    encrypt: bool,
    recipient: &[String],
    age_key_file: Option<&Path>,
    source: &Path,
    target: &Path,
    force: bool,
    dry_run: bool,
) -> Result<(PathBuf, PathBuf), EnstowError> {
    let expanded_file = if let Ok(stripped) = file.strip_prefix("~") {
        target.join(stripped)
    } else {
        file.to_path_buf()
    };

    let target_path = if expanded_file.is_absolute() {
        expanded_file
    } else if expanded_file.exists() {
        std::env::current_dir()
            .map_err(|e| EnstowError::Io {
                path: PathBuf::from("."),
                source: e,
            })?
            .join(&expanded_file)
    } else if target.join(&expanded_file).exists() {
        target.join(&expanded_file)
    } else {
        expanded_file
    };

    let meta = std::fs::symlink_metadata(&target_path).map_err(|e| EnstowError::Io {
        path: target_path.clone(),
        source: e,
    })?;

    if meta.file_type().is_dir() {
        return Err(EnstowError::Config(format!(
            "Cannot add directory '{}': please specify a file",
            target_path.display()
        )));
    }

    let canonical_target_path =
        normalize_path(&target_path.canonicalize().map_err(|e| EnstowError::Io {
            path: target_path.clone(),
            source: e,
        })?);
    let target_root = normalize_path(&target.canonicalize().map_err(|e| EnstowError::Io {
        path: target.to_path_buf(),
        source: e,
    })?);

    let rel_path = canonical_target_path
        .strip_prefix(&target_root)
        .map_err(|_| {
            EnstowError::Config(format!(
                "File '{}' is not within target directory '{}'",
                target_path.display(),
                target_root.display()
            ))
        })?;

    let source_root = normalize_path(&source.canonicalize().map_err(|e| EnstowError::Io {
        path: source.to_path_buf(),
        source: e,
    })?);

    if canonical_target_path.starts_with(&source_root) {
        return Err(EnstowError::Config(format!(
            "File '{}' is already inside source repository",
            target_path.display()
        )));
    }

    let pkg_dir = source_root.join(package);
    let dest_source = if encrypt {
        let mut p = pkg_dir.join(rel_path).into_os_string();
        p.push(".age");
        PathBuf::from(p)
    } else {
        pkg_dir.join(rel_path)
    };

    if (dest_source.exists() || std::fs::symlink_metadata(&dest_source).is_ok()) && !force {
        return Err(EnstowError::Collision { path: dest_source });
    }

    if !encrypt && is_symlink_to(&target_path, &dest_source) {
        return Ok((target_path, dest_source));
    }

    if dry_run {
        if encrypt {
            println!(
                "[dry-run] ENCRYPT {} -> {}",
                target_path.display(),
                dest_source.display()
            );
            println!(
                "[dry-run] DECRYPT {} -> {} (mode 0600)",
                dest_source.display(),
                target_path.display()
            );
        } else {
            println!(
                "[dry-run] ADD {} -> {}",
                target_path.display(),
                dest_source.display()
            );
            println!(
                "[dry-run] LINK  {} -> {}",
                target_path.display(),
                dest_source.display()
            );
        }
        return Ok((target_path, dest_source));
    }

    if encrypt {
        let plaintext = std::fs::read(&target_path).map_err(|e| EnstowError::Io {
            path: target_path.clone(),
            source: e,
        })?;
        let recipient_list = crate::crypto::resolve_age_recipients(recipient, age_key_file)?;
        crate::crypto::encrypt_bytes_age_with_recipients(
            &plaintext,
            &dest_source,
            &recipient_list,
        )?;
        crate::crypto::write_secure_file_with_mode(&target_path, &plaintext, true, 0o600)?;
    } else {
        if let Some(parent) = dest_source.parent() {
            std::fs::create_dir_all(parent).map_err(|e| EnstowError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
        std::fs::copy(&target_path, &dest_source).map_err(|e| EnstowError::Io {
            path: dest_source.clone(),
            source: e,
        })?;
        #[cfg(unix)]
        {
            let _ = std::fs::set_permissions(&dest_source, meta.permissions());
        }
        remove_target(&target_path, &meta)?;
        create_symlink(&dest_source, &target_path, true)?;
    }

    Ok((target_path, dest_source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_plan_stow_identifies_links_and_secrets() {
        let dir = tempdir().unwrap();
        let regular_file = dir.path().join("config.toml");
        let secret_file = dir.path().join("secrets.age");
        std::fs::write(&regular_file, "key = 'val'").unwrap();
        std::fs::write(&secret_file, "encrypted").unwrap();

        let target_dir = tempdir().unwrap();
        let args = CommonArgs {
            source: Some(dir.path().to_path_buf()),
            target: Some(target_dir.path().to_path_buf()),
            dry_run: true,
            ..Default::default()
        };

        let actions = plan_stow(&args).unwrap();
        assert_eq!(actions.len(), 2);
    }

    #[test]
    fn test_normalize_path_strips_verbatim_prefixes() {
        assert_eq!(
            normalize_path(Path::new(r"\\?\C:\path\to\file")),
            Path::new(r"C:\path\to\file")
        );
        assert_eq!(
            normalize_path(Path::new(r"\??\C:\path\to\file")),
            Path::new(r"C:\path\to\file")
        );
        assert_eq!(
            normalize_path(Path::new(r"\\?\UNC\server\share\file")),
            Path::new(r"\\server\share\file")
        );
    }

    #[test]
    fn test_is_stale_scan_ignored_dir() {
        assert!(is_stale_scan_ignored_dir(".git"));
        assert!(is_stale_scan_ignored_dir(".cargo"));
        assert!(is_stale_scan_ignored_dir("target"));
        assert!(is_stale_scan_ignored_dir("node_modules"));
        assert!(!is_stale_scan_ignored_dir(".config"));
        assert!(!is_stale_scan_ignored_dir("dotfiles"));
    }

    #[test]
    fn test_compute_backup_dest() {
        let backup_dir = Path::new("/backup");
        let target_root = Path::new("/home/user");
        let target = Path::new("/home/user/.config/app/cfg.toml");

        // Target inside root
        let dest = compute_backup_dest(target, backup_dir, Some(target_root));
        assert_eq!(
            dest,
            PathBuf::from("/backup")
                .join(".config")
                .join("app")
                .join("cfg.toml")
        );

        // Target outside root
        let outside = Path::new("/etc/passwd");
        let dest_out = compute_backup_dest(outside, backup_dir, Some(target_root));
        assert_eq!(dest_out, PathBuf::from("/backup").join("passwd"));

        // No root
        let dest_no_root = compute_backup_dest(target, backup_dir, None);
        assert_eq!(dest_no_root, PathBuf::from("/backup").join("cfg.toml"));
    }

    #[test]
    fn test_format_backup_timestamp() {
        use std::time::{Duration, UNIX_EPOCH};

        let at = |secs: u64| format_backup_timestamp(UNIX_EPOCH + Duration::from_secs(secs));
        // 1970-01-01 00:00:00 UTC
        assert_eq!(at(0), "19700101_000000");
        // 2000-02-29 12:34:56 UTC (400-year leap day)
        assert_eq!(at(951_827_696), "20000229_123456");
        // 2024-02-29 23:59:59 UTC (leap day)
        assert_eq!(at(1_709_251_199), "20240229_235959");
        // 2025-12-31 23:59:59 UTC (year boundary)
        assert_eq!(at(1_767_225_599), "20251231_235959");
        // 2026-01-01 00:00:00 UTC (new year)
        assert_eq!(at(1_767_225_600), "20260101_000000");
        // 2026-11-22 00:45:00 UTC
        assert_eq!(at(1_795_308_300), "20261122_004500");
        // 2100-03-01 00:00:00 UTC (non-leap century year)
        assert_eq!(at(4_107_542_400), "21000301_000000");
    }

    #[test]
    fn test_resolve_backup_dir_for_run() {
        let dir = tempdir().unwrap();

        // Literal path without {timestamp} stays untouched even when it already exists
        let literal = dir.path().join("literal");
        std::fs::create_dir_all(&literal).unwrap();
        assert_eq!(
            resolve_backup_dir_for_run(&literal, "20261122_004500"),
            literal
        );

        // Template with {timestamp} expands and disambiguates same-second collisions
        let template = dir.path().join(".enstow-backup").join("{timestamp}");
        let first = resolve_backup_dir_for_run(&template, "20261122_004500");
        assert_eq!(
            first,
            dir.path().join(".enstow-backup").join("20261122_004500")
        );

        std::fs::create_dir_all(&first).unwrap();
        let second = resolve_backup_dir_for_run(&template, "20261122_004500");
        assert_eq!(
            second,
            dir.path().join(".enstow-backup").join("20261122_004500_1")
        );

        std::fs::create_dir_all(&second).unwrap();
        let third = resolve_backup_dir_for_run(&template, "20261122_004500");
        assert_eq!(
            third,
            dir.path().join(".enstow-backup").join("20261122_004500_2")
        );

        // Inline and nested {timestamp} placeholder
        let nested_template = dir.path().join("run-{timestamp}").join("nested");
        let n1 = resolve_backup_dir_for_run(&nested_template, "20261122_004500");
        assert_eq!(n1, dir.path().join("run-20261122_004500").join("nested"));
        std::fs::create_dir_all(&n1).unwrap();
        let n2 = resolve_backup_dir_for_run(&nested_template, "20261122_004500");
        assert_eq!(n2, dir.path().join("run-20261122_004500_1").join("nested"));
    }

    #[test]
    fn test_clean_empty_parents() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).unwrap();
        let file = nested.join("test.txt");
        std::fs::write(&file, "hi").unwrap();

        std::fs::remove_file(&file).unwrap();
        clean_empty_parents(&file, dir.path());

        // c, b, a should be removed, while root dir remains
        assert!(!nested.exists());
        assert!(!dir.path().join("a").exists());
        assert!(dir.path().exists());
    }

    #[test]
    fn test_create_symlink_and_is_symlink_to() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("source.txt");
        let other_src = dir.path().join("other_source.txt");
        let tgt = dir.path().join("target.txt");
        std::fs::write(&src, "content").unwrap();
        std::fs::write(&other_src, "other content").unwrap();

        assert!(create_symlink(&src, &tgt, false).is_ok());
        assert!(is_symlink_to(&tgt, &src));
        assert!(!is_symlink_to(&src, &tgt));

        // Idempotent when creating same symlink again
        assert!(create_symlink(&src, &tgt, false).is_ok());

        // Collision when target already exists and points to a different source
        assert!(matches!(
            create_symlink(&other_src, &tgt, false),
            Err(EnstowError::Collision { .. })
        ));

        // With force succeeds and overwrites to other_src
        assert!(create_symlink(&other_src, &tgt, true).is_ok());
        assert!(is_symlink_to(&tgt, &other_src));
    }

    #[test]
    fn test_check_status_symlinks() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("source.txt");
        let tgt = dir.path().join("target.txt");
        std::fs::write(&src, "content").unwrap();

        let action = FileAction::Symlink {
            source: src.clone(),
            target: tgt.clone(),
        };

        // 1. Missing
        let statuses = check_status(std::slice::from_ref(&action), None).unwrap();
        assert_eq!(statuses[0].status, EntryStatus::Missing);

        // 2. Conflict (regular file exists at target)
        std::fs::write(&tgt, "other content").unwrap();
        let statuses = check_status(std::slice::from_ref(&action), None).unwrap();
        assert_eq!(statuses[0].status, EntryStatus::Conflict);

        // 3. Synced
        std::fs::remove_file(&tgt).unwrap();
        create_symlink(&src, &tgt, true).unwrap();
        let statuses = check_status(&[action], None).unwrap();
        assert_eq!(statuses[0].status, EntryStatus::Synced);
    }

    #[test]
    fn test_find_folded_ancestor_ignores_shared_symlinked_root() {
        let dir = tempdir().unwrap();
        let real_root = dir.path().join("real");
        let real_sub = real_root.join("sub");
        std::fs::create_dir_all(&real_sub).unwrap();

        let alias_root = dir.path().join("alias");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_root, &alias_root).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&real_root, &alias_root).unwrap();

        // Shared symlinked root (mirrors macOS /var -> /private/var)
        let src = alias_root.join("sub").join("source.txt");
        let tgt = alias_root.join("sub").join("target.txt");
        std::fs::write(&src, "content").unwrap();

        assert!(find_folded_ancestor(&src, &tgt, None).is_none());
        assert!(create_symlink(&src, &tgt, false).is_ok());
        assert!(is_symlink_to(&tgt, &src));

        std::fs::remove_file(&tgt).unwrap();
        let action = FileAction::Symlink {
            source: src.clone(),
            target: tgt.clone(),
        };
        let statuses = check_status(&[action], None).unwrap();
        assert_eq!(statuses[0].status, EntryStatus::Missing);

        // Unrelated target_root must not walk past root into shared symlinked ancestors
        let unrelated_root = dir.path().join("unrelated");
        std::fs::create_dir_all(&unrelated_root).unwrap();
        assert!(find_folded_ancestor(&src, &tgt, Some(&unrelated_root)).is_none());

        // Real legacy folded directory symlink inside the symlinked root is still detected
        let pkg_dir = alias_root
            .join("dotfiles")
            .join("pkg")
            .join(".config")
            .join("app");
        let home_root = alias_root.join("home");
        let home_cfg = home_root.join(".config");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::create_dir_all(&home_cfg).unwrap();
        let folded = home_cfg.join("app");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&pkg_dir, &folded).unwrap();
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(&pkg_dir, &folded).unwrap();

        let pkg_src = pkg_dir.join("app.conf");
        std::fs::write(&pkg_src, "k=v\n").unwrap();
        let home_tgt = folded.join("app.conf");
        let canon_pkg_src = pkg_src.canonicalize().unwrap();

        assert!(find_folded_ancestor(&pkg_src, &home_tgt, None).is_some());
        assert!(find_folded_ancestor(&pkg_src, &home_tgt, Some(&home_root)).is_some());
        assert!(find_folded_ancestor(&canon_pkg_src, &home_tgt, None).is_some());
        assert!(find_folded_ancestor(&canon_pkg_src, &home_tgt, Some(&home_root)).is_some());
    }

    #[test]
    fn test_execute_plan_and_unstow_plan() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src.txt");
        let tgt = dir.path().join("sub").join("tgt.txt");
        std::fs::write(&src, "hello stow").unwrap();

        let action = FileAction::Symlink {
            source: src.clone(),
            target: tgt.clone(),
        };

        // Dry run
        assert!(execute_plan(std::slice::from_ref(&action), true, None, false).is_ok());
        assert!(std::fs::symlink_metadata(&tgt).is_err());

        // Real execute
        assert!(execute_plan(std::slice::from_ref(&action), false, None, false).is_ok());
        assert!(is_symlink_to(&tgt, &src));

        // Unstow
        assert!(execute_unstow_plan(&[action], dir.path(), false).is_ok());
        assert!(std::fs::symlink_metadata(&tgt).is_err());
    }

    #[test]
    fn test_find_age_secrets() {
        let dir = tempdir().unwrap();
        let pkg = dir.path().join("mypkg");
        std::fs::create_dir_all(&pkg).unwrap();
        let normal = pkg.join("app.conf");
        let age_secret = pkg.join("pass.age");
        std::fs::write(&normal, "setting = 1").unwrap();
        std::fs::write(&age_secret, "encrypted").unwrap();

        let secrets = find_age_secrets(dir.path(), &["mypkg".to_string()], &[]).unwrap();
        assert_eq!(secrets.len(), 1);
        assert!(secrets[0].ends_with("pass.age"));
    }

    #[test]
    fn test_add_file_symlink() {
        let dir = tempdir().unwrap();
        let canon_root = normalize_path(&dir.path().canonicalize().unwrap());
        let src_root = canon_root.join("dotfiles");
        let tgt_root = canon_root.join("home");
        let pkg_dir = src_root.join("zsh");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::create_dir_all(&tgt_root).unwrap();

        let target_file = tgt_root.join(".zshrc");
        std::fs::write(&target_file, "export PATH=$PATH:/bin").unwrap();

        // Dry run
        let (t, s) = add_file(
            &target_file,
            "zsh",
            false,
            &[],
            None,
            &src_root,
            &tgt_root,
            false,
            true,
        )
        .unwrap();
        assert_eq!(normalize_path(&t), normalize_path(&target_file));
        assert_eq!(normalize_path(&s), normalize_path(&pkg_dir.join(".zshrc")));
        assert!(!pkg_dir.join(".zshrc").exists());

        // Real add
        let (t, s) = add_file(
            &target_file,
            "zsh",
            false,
            &[],
            None,
            &src_root,
            &tgt_root,
            false,
            false,
        )
        .unwrap();
        assert_eq!(normalize_path(&t), normalize_path(&target_file));
        assert!(s.is_file());
        assert!(is_symlink_to(&target_file, &s));
    }
}
