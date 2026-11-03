use crate::error::EnstowError;
use crate::stow::{is_symlink_to, FileAction};
use similar::{ChangeTag, TextDiff};
use std::fmt::Write as FmtWrite;
use std::path::Path;

#[derive(Debug, PartialEq, Eq, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileDiff {
    pub action: FileAction,
    pub is_secret: bool,
    pub diff: String,
}

fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8000).any(|&b| b == 0)
}

fn format_unified_diff(
    source_name: &str,
    target_name: &str,
    old_content: &str,
    new_content: &str,
    mask_secrets: bool,
) -> Option<String> {
    let diff = TextDiff::from_lines(old_content, new_content);
    if diff.ratio() == 1.0 && old_content == new_content {
        return None;
    }

    let mut out = String::new();
    if mask_secrets {
        let mut has_changes = false;
        let groups = diff.grouped_ops(3);
        if groups.is_empty() {
            return None;
        }

        let _ = writeln!(out, "--- {source_name}");
        let _ = writeln!(out, "+++ {target_name}");

        for group in groups {
            let old_start = group
                .first()
                .map(|op| op.old_range().start + 1)
                .unwrap_or(1);
            let old_len: usize = group.iter().map(|op| op.old_range().len()).sum();
            let new_start = group
                .first()
                .map(|op| op.new_range().start + 1)
                .unwrap_or(1);
            let new_len: usize = group.iter().map(|op| op.new_range().len()).sum();
            let _ = writeln!(out, "@@ -{old_start},{old_len} +{new_start},{new_len} @@");

            for op in group {
                for change in diff.iter_changes(&op) {
                    has_changes = true;
                    match change.tag() {
                        ChangeTag::Delete => {
                            let _ = writeln!(out, "-[MASKED]");
                        }
                        ChangeTag::Insert => {
                            let _ = writeln!(out, "+[MASKED]");
                        }
                        ChangeTag::Equal => {
                            let _ = writeln!(out, " [MASKED]");
                        }
                    }
                }
            }
        }
        if has_changes {
            Some(out)
        } else {
            None
        }
    } else {
        let s = diff
            .unified_diff()
            .header(source_name, target_name)
            .to_string();
        if s.trim().is_empty() {
            None
        } else {
            Some(s)
        }
    }
}

fn generate_diff_text(
    source_name: &str,
    target_name: &str,
    source_bytes: &[u8],
    target_bytes: &[u8],
    mask_secrets: bool,
) -> Option<String> {
    if source_bytes == target_bytes {
        return None;
    }

    if is_binary(source_bytes) || is_binary(target_bytes) {
        return Some(format!(
            "Binary files {} and {} differ\n",
            source_name, target_name
        ));
    }

    let source_str = String::from_utf8_lossy(source_bytes);
    let target_str = String::from_utf8_lossy(target_bytes);

    format_unified_diff(
        source_name,
        target_name,
        &source_str,
        &target_str,
        mask_secrets,
    )
}

pub fn compute_diff(
    actions: &[FileAction],
    age_key_file: Option<&Path>,
    mask_secrets: bool,
) -> Result<Vec<FileDiff>, EnstowError> {
    let mut diffs = Vec::new();

    for action in actions {
        match action {
            FileAction::Symlink { source, target } => {
                if is_symlink_to(target, source) {
                    continue;
                }

                let source_bytes = std::fs::read(source).map_err(|e| EnstowError::Io {
                    path: source.to_path_buf(),
                    source: e,
                })?;

                let target_bytes = if target.exists() || std::fs::symlink_metadata(target).is_ok() {
                    std::fs::read(target).unwrap_or_default()
                } else {
                    Vec::new()
                };

                if target.exists() && source_bytes == target_bytes {
                    continue;
                }

                if let Some(diff_text) = generate_diff_text(
                    &source.display().to_string(),
                    &target.display().to_string(),
                    &source_bytes,
                    &target_bytes,
                    false,
                ) {
                    diffs.push(FileDiff {
                        action: action.clone(),
                        is_secret: false,
                        diff: diff_text,
                    });
                }
            }
            FileAction::Decrypt { source, target } => {
                let secret_type = crate::crypto::detect_secret_type(source).ok_or_else(|| {
                    EnstowError::Config(format!("Unrecognized secret format: {}", source.display()))
                })?;

                let decrypted =
                    crate::crypto::decrypt_to_memory(source, secret_type, age_key_file)?;

                let target_bytes = if target.exists()
                    && !std::fs::symlink_metadata(target)
                        .map(|m| m.file_type().is_symlink() || m.is_dir())
                        .unwrap_or(false)
                {
                    std::fs::read(target).unwrap_or_default()
                } else {
                    Vec::new()
                };

                if target.exists() && decrypted == target_bytes {
                    continue;
                }

                if let Some(diff_text) = generate_diff_text(
                    &source.display().to_string(),
                    &target.display().to_string(),
                    &decrypted,
                    &target_bytes,
                    mask_secrets,
                ) {
                    diffs.push(FileDiff {
                        action: action.clone(),
                        is_secret: true,
                        diff: diff_text,
                    });
                }
            }
        }
    }

    Ok(diffs)
}

pub fn colorize_diff(diff: &str) -> String {
    let mut out = String::new();
    for line in diff.lines() {
        if line.starts_with("---") || line.starts_with("+++") {
            out.push_str("\x1b[1m");
            out.push_str(line);
            out.push_str("\x1b[0m\n");
        } else if line.starts_with("@@") {
            out.push_str("\x1b[36m");
            out.push_str(line);
            out.push_str("\x1b[0m\n");
        } else if line.starts_with('-') {
            out.push_str("\x1b[31m");
            out.push_str(line);
            out.push_str("\x1b[0m\n");
        } else if line.starts_with('+') {
            out.push_str("\x1b[32m");
            out.push_str(line);
            out.push_str("\x1b[0m\n");
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}
