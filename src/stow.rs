use crate::cli::CommonArgs;
use crate::crypto::{detect_secret_type, target_plaintext_name};
use crate::error::EnstowError;
use std::path::{Path, PathBuf};
use tracing::info;
use walkdir::WalkDir;

#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize)]
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
    let source_root = source_path.canonicalize().map_err(|e| EnstowError::Io {
        path: source_path.to_path_buf(),
        source: e,
    })?;

    let mut root_ignore_patterns = load_ignore_patterns(&source_root);
    root_ignore_patterns.extend(args.ignore.clone());

    let pkg_roots = if args.packages.is_empty() {
        vec![source_root.clone()]
    } else {
        let mut roots = Vec::new();
        for pkg in &args.packages {
            let pkg_path = source_root.join(pkg);
            let canonical = pkg_path.canonicalize().map_err(|e| EnstowError::Io {
                path: pkg_path.clone(),
                source: e,
            })?;
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
        let mut ignore_patterns = root_ignore_patterns.clone();
        if pkg_root != source_root {
            ignore_patterns.extend(load_ignore_patterns(&pkg_root));
        }

        for entry in WalkDir::new(&pkg_root)
            .min_depth(1)
            .into_iter()
            .filter_entry(|e| {
                !is_ignored(e.file_name().to_str().unwrap_or_default(), &ignore_patterns)
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
                    let belongs_to_pkg = pkg_roots.iter().any(|pkg_root| {
                        let norm_pkg = normalize_path(pkg_root);
                        norm_dest.starts_with(&norm_pkg)
                            || full_dest
                                .canonicalize()
                                .map(|c| normalize_path(&c).starts_with(&norm_pkg))
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
                            stale_actions.push(FileAction::Symlink {
                                source: full_dest,
                                target: symlink_path.to_path_buf(),
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
    for action in actions {
        match action {
            FileAction::Symlink { source, target } => {
                if is_symlink_to(target, source) {
                    continue;
                }

                if let Ok(meta) = std::fs::symlink_metadata(target) {
                    if !force && !backup {
                        return Err(EnstowError::Collision {
                            path: target.to_path_buf(),
                        });
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
                let target_exists = std::fs::symlink_metadata(target).is_ok();
                if target_exists {
                    if !force && !backup {
                        return Err(EnstowError::Collision {
                            path: target.to_path_buf(),
                        });
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
                            "[dry-run] DECRYPT {} -> {} (mode 0600)",
                            source.display(),
                            target.display()
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
                        "[dry-run] DECRYPT {} -> {} (mode 0600)",
                        source.display(),
                        target.display()
                    );
                    continue;
                }

                info!("Decrypting {} -> {}", source.display(), target.display());
                let secret_type = detect_secret_type(source).ok_or_else(|| {
                    EnstowError::Config(format!("Unrecognized secret format: {}", source.display()))
                })?;
                let plaintext =
                    crate::crypto::decrypt_to_memory(source, secret_type, age_key_file)?;
                crate::crypto::write_secure_file(target, &plaintext, force)?;
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

fn load_ignore_patterns(root: &Path) -> Vec<String> {
    let mut patterns = Vec::new();
    let candidates = [root.join(".enstowignore"), root.join(".stow-local-ignore")];

    for file in candidates {
        if let Ok(content) = std::fs::read_to_string(&file) {
            for line in content.lines() {
                let trimmed = line.trim();
                if !trimmed.is_empty() && !trimmed.starts_with('#') {
                    patterns.push(trimmed.to_string());
                }
            }
        }
    }

    patterns
}

fn is_ignored(name: &str, patterns: &[String]) -> bool {
    let default_ignored = matches!(
        name,
        ".git"
            | ".gitignore"
            | ".codegraph"
            | ".serena"
            | ".agents"
            | ".github"
            | "target"
            | "Cargo.lock"
            | ".enstowignore"
            | ".stow-local-ignore"
    );

    if default_ignored {
        return true;
    }

    for pattern in patterns {
        if glob_matches(pattern, name) {
            return true;
        }
    }

    false
}

fn glob_matches(pattern: &str, text: &str) -> bool {
    if pattern == text {
        return true;
    }

    if let Some(suffix) = pattern.strip_prefix('*') {
        if !suffix.contains('*') {
            return text.ends_with(suffix);
        }
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        if !prefix.contains('*') {
            return text.starts_with(prefix);
        }
    }

    // Ponytail simple wildcard matching
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 2 {
        return text.starts_with(parts[0]) && text.ends_with(parts[1]);
    }

    false
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
            force: false,
            prune: false,
            age_key_file: None,
            packages: Vec::new(),
            ignore: Vec::new(),
            backup: false,
            backup_dir: None,
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
