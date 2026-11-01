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

#[derive(Debug, PartialEq, Eq, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryStatus {
    Synced,
    Missing,
    Conflict,
}

#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize)]
pub struct FileActionStatus {
    pub action: FileAction,
    pub status: EntryStatus,
}

pub fn check_status(actions: &[FileAction]) -> Result<Vec<FileActionStatus>, EnstowError> {
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
            FileAction::Decrypt { source: _, target } => {
                if target.exists() {
                    EntryStatus::Synced
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
    let source_root = args.source.canonicalize().map_err(|e| EnstowError::Io {
        path: args.source.clone(),
        source: e,
    })?;

    let ignore_patterns = load_ignore_patterns(&source_root);

    let mut actions = Vec::new();

    for entry in WalkDir::new(&source_root)
        .min_depth(1)
        .into_iter()
        .filter_entry(|e| !is_ignored(e.file_name().to_str().unwrap_or_default(), &ignore_patterns))
    {
        let entry = entry.map_err(|e| EnstowError::Io {
            path: e.path().unwrap_or(&source_root).to_path_buf(),
            source: std::io::Error::other(e.to_string()),
        })?;

        let path = entry.path();
        if path.is_dir() {
            continue;
        }

        let rel_path = path.strip_prefix(&source_root).map_err(|_| {
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
                target: args.target.join(target_rel),
            });
        } else {
            actions.push(FileAction::Symlink {
                source: path.to_path_buf(),
                target: args.target.join(rel_path),
            });
        }
    }

    Ok(actions)
}

pub fn execute_plan(
    actions: &[FileAction],
    dry_run: bool,
    age_key_file: Option<&Path>,
    force: bool,
) -> Result<(), EnstowError> {
    for action in actions {
        match action {
            FileAction::Symlink { source, target } => {
                if dry_run {
                    println!(
                        "[dry-run] LINK  {} -> {}",
                        target.display(),
                        source.display()
                    );
                } else {
                    create_symlink(source, target, force)?;
                }
            }
            FileAction::Decrypt { source, target } => {
                if dry_run {
                    println!(
                        "[dry-run] DECRYPT {} -> {} (mode 0600)",
                        source.display(),
                        target.display()
                    );
                } else {
                    info!("Decrypting {} -> {}", source.display(), target.display());
                    let secret_type = detect_secret_type(source).ok_or_else(|| {
                        EnstowError::Config(format!(
                            "Unrecognized secret format: {}",
                            source.display()
                        ))
                    })?;
                    let plaintext =
                        crate::crypto::decrypt_to_memory(source, secret_type, age_key_file)?;
                    crate::crypto::write_secure_file(target, &plaintext, force)?;
                }
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
    let mut current = path.parent();
    while let Some(dir) = current {
        if let Ok(c) = dir.canonicalize() {
            if c == stop_at {
                break;
            }
        }
        if dir == stop_at {
            break;
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
                if let (Ok(c1), Ok(c2)) = (full_dest.canonicalize(), expected_source.canonicalize())
                {
                    return c1 == c2;
                }
            }
        }
    }
    false
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
        if meta.file_type().is_dir() {
            std::fs::remove_dir_all(target).map_err(|e| EnstowError::Io {
                path: target.to_path_buf(),
                source: e,
            })?;
        } else {
            std::fs::remove_file(target).map_err(|e| EnstowError::Io {
                path: target.to_path_buf(),
                source: e,
            })?;
        }
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
            source: dir.path().to_path_buf(),
            target: target_dir.path().to_path_buf(),
            dry_run: true,
            force: false,
            age_key_file: None,
        };

        let actions = plan_stow(&args).unwrap();
        assert_eq!(actions.len(), 2);
    }
}
