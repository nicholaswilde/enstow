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
        vec![source_root]
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

fn is_stale_scan_ignored_dir(name: &str) -> bool {
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
    for action in actions {
        match action {
            FileAction::Symlink { source, target } => {
                if is_symlink_to(target, source) {
                    continue;
                }

                if let Ok(meta) = std::fs::symlink_metadata(target) {
                    if !force && !backup && !adopt {
                        return Err(EnstowError::Collision {
                            path: target.to_path_buf(),
                        });
                    }

                    if adopt {
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

                    let backup_dest =
                        backup_dir.map(|bd| compute_backup_dest(target, bd, target_root));

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
                        }
                    } else if force {
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

                create_symlink(source, target, force)?;
            }
            FileAction::Decrypt { source, target } => {
                let mode = permissions
                    .map(|p| p.resolve_mode(target, Some(source), target_root))
                    .unwrap_or(0o600);
                let target_exists = std::fs::symlink_metadata(target).is_ok();
                if target_exists {
                    if !force && !backup && !adopt {
                        return Err(EnstowError::Collision {
                            path: target.to_path_buf(),
                        });
                    }

                    if adopt {
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
                        let recipients = crate::crypto::resolve_age_recipients(&[], age_key_file)?;
                        crate::crypto::encrypt_bytes_age_with_recipients(
                            &plaintext,
                            source,
                            &recipients,
                        )?;
                        crate::crypto::write_secure_file_with_mode(target, &plaintext, true, mode)?;
                        continue;
                    }

                    let backup_dest =
                        backup_dir.map(|bd| compute_backup_dest(target, bd, target_root));

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
                        }
                    } else if force {
                        if let Ok(meta) = std::fs::symlink_metadata(target) {
                            remove_target(target, &meta)?;
                        }
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
                let secret_type = detect_secret_type(source).ok_or_else(|| {
                    EnstowError::Config(format!("Unrecognized secret format: {}", source.display()))
                })?;
                let plaintext =
                    crate::crypto::decrypt_to_memory(source, secret_type, age_key_file)?;
                crate::crypto::write_secure_file_with_mode(target, &plaintext, force, mode)?;
            }
        }
    }
    Ok(())
}

pub fn execute_unstow_plan(
    actions: &[FileAction],
    target_root: &Path,
    dry_run: bool,
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
                        std::fs::remove_file(target).map_err(|e| EnstowError::Io {
                            path: target.to_path_buf(),
                            source: e,
                        })?;
                        clean_empty_parents(target, &target_canonical);
                    }
                }
            }
            FileAction::Decrypt { source: _, target } => {
                if target.exists() {
                    if dry_run {
                        println!("[dry-run] REMOVE SECRET {}", target.display());
                    } else {
                        info!("Removing secret {}", target.display());
                        std::fs::remove_file(target).map_err(|e| EnstowError::Io {
                            path: target.to_path_buf(),
                            source: e,
                        })?;
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

fn remove_target(target: &Path, meta: &std::fs::Metadata) -> Result<(), EnstowError> {
    if meta.file_type().is_dir() {
        std::fs::remove_dir_all(target).map_err(|e| EnstowError::Io {
            path: target.to_path_buf(),
            source: e,
        })
    } else {
        std::fs::remove_file(target).map_err(|e| EnstowError::Io {
            path: target.to_path_buf(),
            source: e,
        })
    }
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
}
