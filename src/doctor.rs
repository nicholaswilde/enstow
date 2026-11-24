use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::cli::CommonArgs;
use crate::config::PermissionsConfig;
use crate::crypto::{self, SecretType};
use crate::error::EnstowError;
use crate::stow::{
    best_target_root_for, is_stale_scan_ignored_dir, normalize_path, permission_roots_for,
    plan_prune_from_symlinks, plan_stow, resolve_pkg_groups_by_target, scan_target_symlinks,
    FileAction, TargetScanScope,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckSeverity {
    Ok,
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DoctorCheck {
    pub category: String,
    pub severity: CheckSeverity,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
    pub total_checks: usize,
    pub ok: usize,
    pub warnings: usize,
    pub errors: usize,
    pub healthy: bool,
}

impl DoctorReport {
    pub fn new(checks: Vec<DoctorCheck>) -> Self {
        let ok = checks
            .iter()
            .filter(|c| c.severity == CheckSeverity::Ok)
            .count();
        let warnings = checks
            .iter()
            .filter(|c| c.severity == CheckSeverity::Warning)
            .count();
        let errors = checks
            .iter()
            .filter(|c| c.severity == CheckSeverity::Error)
            .count();
        let total_checks = checks.len();
        let healthy = errors == 0;

        Self {
            checks,
            total_checks,
            ok,
            warnings,
            errors,
            healthy,
        }
    }
}

/// Run all doctor checks for system health, secret hygiene, permissions, and symlinks.
pub fn run_doctor(
    args: &CommonArgs,
    permissions: Option<&PermissionsConfig>,
) -> Result<DoctorReport, EnstowError> {
    let actions = plan_stow(args)?;
    let mut checks = Vec::new();

    let target_roots = args.active_target_roots();
    checks.extend(check_package_collisions(&actions));
    checks.extend(check_symlink_health(args, &actions)?);
    checks.extend(check_secret_permissions(
        &actions,
        &target_roots,
        permissions,
    ));
    checks.extend(check_decryption_prerequisites(args, &actions));
    checks.extend(check_plaintext_secret_guard(args, &actions));
    checks.extend(check_leak_scan(&actions));

    Ok(DoctorReport::new(checks))
}

#[derive(Clone, Copy)]
enum GitAuditMode {
    Staged,
    Tracked,
}

/// Inspect git staged files (`git diff --cached --name-only --diff-filter=ACM`) for
/// plaintext counterparts of encrypted files, forbidden secret filenames, and credential leaks.
pub fn run_doctor_staged(source_dir: &Path) -> Result<DoctorReport, EnstowError> {
    run_doctor_git_files(source_dir, GitAuditMode::Staged)
}

/// Audit all git-tracked files (`git ls-files -z`) across the repository for
/// plaintext counterparts of encrypted files, forbidden secret filenames, and credential leaks.
pub fn run_doctor_tracked(source_dir: &Path) -> Result<DoctorReport, EnstowError> {
    run_doctor_git_files(source_dir, GitAuditMode::Tracked)
}

fn read_git_index_blob(git_root: &Path, rel: &str) -> Option<Vec<u8>> {
    std::process::Command::new("git")
        .args(["show", &format!(":{rel}")])
        .current_dir(git_root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| o.stdout)
}

fn read_bounded_regular_file(path: &Path) -> Option<Vec<u8>> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() || meta.len() > 1_000_000 {
        return None;
    }
    fs::read(path).ok()
}

fn run_doctor_git_files(
    source_dir: &Path,
    mode: GitAuditMode,
) -> Result<DoctorReport, EnstowError> {
    let top_out = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(source_dir)
        .output()
        .map_err(|e| {
            EnstowError::Config(format!(
                "Failed to invoke git in '{}': {e}",
                source_dir.display()
            ))
        })?;
    if !top_out.status.success() {
        let stderr = String::from_utf8_lossy(&top_out.stderr);
        return Err(EnstowError::Config(format!(
            "Directory '{}' is not inside a git repository: {}",
            source_dir.display(),
            stderr.trim()
        )));
    }
    let git_root_str = String::from_utf8_lossy(&top_out.stdout).trim().to_string();
    let git_root = PathBuf::from(&git_root_str);
    let canon_root = normalize_path(&git_root.canonicalize().unwrap_or_else(|_| git_root.clone()));

    let (git_args, scope_word, label): (&[&str], &str, &str) = match mode {
        GitAuditMode::Staged => (
            &["diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"],
            "staged",
            "Staged",
        ),
        GitAuditMode::Tracked => (&["ls-files", "-z"], "tracked", "Tracked"),
    };

    let list_out = std::process::Command::new("git")
        .args(git_args)
        .current_dir(&git_root)
        .output()
        .map_err(|e| {
            EnstowError::Config(format!(
                "Failed to list {scope_word} files in '{}': {e}",
                git_root.display()
            ))
        })?;
    if !list_out.status.success() {
        let stderr = String::from_utf8_lossy(&list_out.stderr);
        return Err(EnstowError::Config(format!(
            "Failed to inspect git {scope_word} files in '{}': {}",
            git_root.display(),
            stderr.trim()
        )));
    }

    let rel_paths: Vec<String> = list_out
        .stdout
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();

    let counterparts: HashMap<PathBuf, PathBuf> =
        collect_encrypted_counterparts(std::slice::from_ref(&canon_root))
            .into_iter()
            .map(|(enc, plain)| (normalize_path(&plain), enc))
            .collect();

    let mut checks = Vec::new();
    for rel in &rel_paths {
        let full_path = rel
            .split('/')
            .fold(canon_root.clone(), |acc, part| acc.join(part));
        let norm_full = normalize_path(&full_path);

        // Encrypted files themselves (.age, .sops.*) are safe to stage/track
        if matches!(
            crypto::detect_secret_type(&full_path),
            Some(SecretType::Age | SecretType::Sops)
        ) {
            continue;
        }

        if let Some(encrypted_src) = counterparts.get(&norm_full) {
            checks.push(DoctorCheck {
                category: "secret_guard".into(),
                severity: CheckSeverity::Error,
                message: format!(
                    "{label} plaintext secret '{}' has encrypted counterpart '{}' — encrypt instead of committing plaintext",
                    rel,
                    encrypted_src.display()
                ),
                path: Some(full_path.clone()),
            });
        }

        if is_forbidden_dotenv(&full_path) {
            checks.push(DoctorCheck {
                category: "secret_guard".into(),
                severity: CheckSeverity::Error,
                message: format!(
                    "{label} unencrypted .env file '{}' — add to .gitignore or encrypt with 'enstow encrypt'",
                    rel
                ),
                path: Some(full_path.clone()),
            });
        }

        if is_forbidden_key_file(&full_path) {
            checks.push(DoctorCheck {
                category: "secret_guard".into(),
                severity: CheckSeverity::Error,
                message: format!(
                    "{label} private key file '{}' — add to .gitignore or encrypt with 'enstow encrypt'",
                    rel
                ),
                path: Some(full_path.clone()),
            });
        }

        let file_bytes = match mode {
            // Scan staged index blob (fallback to working tree regular file if git show fails)
            GitAuditMode::Staged => read_git_index_blob(&git_root, rel)
                .or_else(|| read_bounded_regular_file(&full_path)),
            // Read regular working-tree file without following symlinks (fallback to index blob if absent)
            GitAuditMode::Tracked => match fs::symlink_metadata(&full_path) {
                Ok(meta) if meta.file_type().is_file() && meta.len() <= 1_000_000 => {
                    fs::read(&full_path).ok()
                }
                Ok(_) => None,
                Err(_) => read_git_index_blob(&git_root, rel),
            },
        };

        if let Some(bytes) = file_bytes {
            if bytes.len() <= 1_000_000 {
                if let Ok(content) = std::str::from_utf8(&bytes) {
                    if let Some(desc) = scan_content_for_leaks(content) {
                        checks.push(DoctorCheck {
                            category: "leak_scan".into(),
                            severity: CheckSeverity::Error,
                            message: format!(
                                "{label} credential leak detected in '{}': {}",
                                rel, desc
                            ),
                            path: Some(full_path),
                        });
                    }
                }
            }
        }
    }

    if checks.is_empty() {
        checks.push(DoctorCheck {
            category: "secret_guard".into(),
            severity: CheckSeverity::Ok,
            message: format!(
                "No plaintext secrets or credential leaks found in {} {scope_word} file(s)",
                rel_paths.len()
            ),
            path: None,
        });
    }

    Ok(DoctorReport::new(checks))
}

fn check_package_collisions(actions: &[FileAction]) -> Vec<DoctorCheck> {
    let mut targets: HashMap<PathBuf, Vec<PathBuf>> = HashMap::new();
    for action in actions {
        let norm_target = normalize_path(action.target());
        targets
            .entry(norm_target)
            .or_default()
            .push(action.source().to_path_buf());
    }

    let mut checks = Vec::new();
    let mut collisions_found = false;

    for (target, sources) in targets {
        if sources.len() > 1 {
            collisions_found = true;
            checks.push(DoctorCheck {
                category: "package_collisions".into(),
                severity: CheckSeverity::Error,
                message: format!(
                    "Package collision on '{}': mapped from {} sources: {:?}",
                    target.display(),
                    sources.len(),
                    sources
                ),
                path: Some(target),
            });
        }
    }

    if !collisions_found {
        checks.push(DoctorCheck {
            category: "package_collisions".into(),
            severity: CheckSeverity::Ok,
            message: "No package destination collisions detected".into(),
            path: None,
        });
    }

    checks
}

fn collect_dangling_symlink_checks(
    target_path: &Path,
    target_canonical: &Path,
    scanned_symlinks: &[PathBuf],
    reported_paths: &mut HashSet<PathBuf>,
    checks: &mut Vec<DoctorCheck>,
) {
    let norm_tc = normalize_path(target_canonical);
    for symlink_path in scanned_symlinks {
        let Ok(dest) = fs::read_link(symlink_path) else {
            continue;
        };
        let full_dest = if dest.is_relative() {
            symlink_path.parent().map(|p| p.join(&dest)).unwrap_or(dest)
        } else {
            dest
        };
        if full_dest.exists() {
            continue;
        }
        let norm_sp = normalize_path(symlink_path);
        let rebased = symlink_path
            .strip_prefix(target_canonical)
            .or_else(|_| norm_sp.strip_prefix(&norm_tc))
            .map(|rel| target_path.join(rel))
            .unwrap_or_else(|_| symlink_path.clone());
        let norm_rebased = normalize_path(&rebased);
        if reported_paths.contains(&norm_sp) || reported_paths.contains(&norm_rebased) {
            continue;
        }
        reported_paths.insert(symlink_path.clone());
        reported_paths.insert(norm_sp);
        reported_paths.insert(rebased.clone());
        reported_paths.insert(norm_rebased);
        checks.push(DoctorCheck {
            category: "symlink_health".into(),
            severity: CheckSeverity::Error,
            message: format!(
                "Dangling symlink pointing to nonexistent path: {} -> {}",
                symlink_path.display(),
                full_dest.display()
            ),
            path: Some(symlink_path.clone()),
        });
    }
}

fn check_symlink_health(
    args: &CommonArgs,
    actions: &[FileAction],
) -> Result<Vec<DoctorCheck>, EnstowError> {
    let mut checks = Vec::new();
    let (source_root, target_groups) = resolve_pkg_groups_by_target(args)?;
    let target_roots: Vec<PathBuf> = if target_groups.is_empty() {
        args.active_target_roots()
    } else {
        target_groups.iter().map(|(t, _)| t.clone()).collect()
    };

    let existing_groups: Vec<(PathBuf, Vec<PathBuf>)> = target_groups
        .into_iter()
        .filter(|(t, _)| t.exists())
        .collect();

    if existing_groups.is_empty() {
        let missing_target = target_roots
            .first()
            .cloned()
            .unwrap_or_else(|| args.target_path());
        checks.push(DoctorCheck {
            category: "symlink_health".into(),
            severity: CheckSeverity::Ok,
            message: format!(
                "Target destination directory does not exist yet: {}",
                missing_target.display()
            ),
            path: Some(missing_target),
        });
        return Ok(checks);
    }

    let mut reported_paths = HashSet::new();
    let mut scanned_by_target: Vec<(&PathBuf, PathBuf, Vec<PathBuf>)> = Vec::new();

    for (target_path, scoped_pkg_roots) in &existing_groups {
        let target_canonical = target_path
            .canonicalize()
            .unwrap_or_else(|_| target_path.clone());

        let scope = TargetScanScope {
            source_root: &source_root,
            target_path,
            target_canonical: &target_canonical,
            scoped_pkg_roots,
        };
        let scanned_symlinks = scan_target_symlinks(args, actions, &scope);

        // 1. Scan managed target subtrees for dangling symlinks
        collect_dangling_symlink_checks(
            target_path,
            &target_canonical,
            &scanned_symlinks,
            &mut reported_paths,
            &mut checks,
        );

        scanned_by_target.push((target_path, target_canonical, scanned_symlinks));
    }

    // 2. Detect legacy GNU Stow folded directory symlinks pointing into source packages
    for action in actions {
        let action_target_root = best_target_root_for(action.target(), &target_roots);
        if let Some((folded_path, resolved_dest)) =
            crate::stow::find_folded_ancestor(action.source(), action.target(), action_target_root)
        {
            let norm_folded = normalize_path(&folded_path);
            if reported_paths.insert(norm_folded) {
                reported_paths.insert(folded_path.clone());
                checks.push(DoctorCheck {
                    category: "symlink_health".into(),
                    severity: CheckSeverity::Warning,
                    message: format!(
                        "Legacy folded directory symlink pointing into source repository: {} -> {} (run `enstow apply` or `enstow restow` to unfold)",
                        folded_path.display(),
                        resolved_dest.display()
                    ),
                    path: Some(folded_path),
                });
            }
        }
    }

    // 3. Scan for stale symlinks belonging to managed dotfiles no longer active
    for (target_path, target_canonical, scanned_symlinks) in &scanned_by_target {
        if let Ok(stale_actions) = plan_prune_from_symlinks(
            args,
            actions,
            target_path,
            target_canonical,
            scanned_symlinks,
        ) {
            for stale in stale_actions {
                let target = stale.target().to_path_buf();
                let norm_target = normalize_path(&target);
                if !reported_paths.contains(&target) && !reported_paths.contains(&norm_target) {
                    reported_paths.insert(target.clone());
                    reported_paths.insert(norm_target);
                    checks.push(DoctorCheck {
                        category: "symlink_health".into(),
                        severity: CheckSeverity::Warning,
                        message: format!(
                            "Stale symlink from previous package: {} -> {}",
                            stale.target().display(),
                            stale.source().display()
                        ),
                        path: Some(target),
                    });
                }
            }
        }
    }

    // 4. Verify active symlink actions
    let symlink_actions_count = actions
        .iter()
        .filter(|a| matches!(a, FileAction::Symlink { .. }))
        .count();

    if checks.is_empty() {
        checks.push(DoctorCheck {
            category: "symlink_health".into(),
            severity: CheckSeverity::Ok,
            message: format!(
                "Symlink health verified across {} active dotfiles",
                symlink_actions_count
            ),
            path: None,
        });
    }

    Ok(checks)
}

fn check_secret_permissions(
    actions: &[FileAction],
    target_roots: &[PathBuf],
    permissions: Option<&PermissionsConfig>,
) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    let decrypt_actions: Vec<_> = actions
        .iter()
        .filter_map(|a| match a {
            FileAction::Decrypt { source, target } => Some((source, target)),
            _ => None,
        })
        .collect();

    if decrypt_actions.is_empty() {
        checks.push(DoctorCheck {
            category: "secret_permissions".into(),
            severity: CheckSeverity::Ok,
            message: "No decrypted secret targets configured in active packages".into(),
            path: None,
        });
        return checks;
    }

    for (source, target) in decrypt_actions {
        if target.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = fs::symlink_metadata(target) {
                    let actual_mode = meta.permissions().mode() & 0o777;
                    let perm_roots = permission_roots_for(target, target_roots);
                    let expected_mode = permissions
                        .map(|p| p.resolve_mode_for_roots(target, Some(source), &perm_roots))
                        .unwrap_or(0o600);

                    if actual_mode != expected_mode {
                        checks.push(DoctorCheck {
                            category: "secret_permissions".into(),
                            severity: CheckSeverity::Error,
                            message: format!(
                                "Insecure secret permissions on '{}': mode is {:04o}, expected {:04o}",
                                target.display(),
                                actual_mode,
                                expected_mode
                            ),
                            path: Some(target.clone()),
                        });
                    } else {
                        checks.push(DoctorCheck {
                            category: "secret_permissions".into(),
                            severity: CheckSeverity::Ok,
                            message: format!(
                                "Strict secret permissions verified on '{}' ({:04o})",
                                target.display(),
                                actual_mode
                            ),
                            path: Some(target.clone()),
                        });
                    }
                }
            }

            #[cfg(not(unix))]
            {
                let _ = (source, permissions, target_roots);
                checks.push(DoctorCheck {
                    category: "secret_permissions".into(),
                    severity: CheckSeverity::Ok,
                    message: format!(
                        "Secret target exists (Unix permissions check skipped on non-Unix platform): {}",
                        target.display()
                    ),
                    path: Some(target.clone()),
                });
            }
        } else {
            checks.push(DoctorCheck {
                category: "secret_permissions".into(),
                severity: CheckSeverity::Ok,
                message: format!(
                    "Secret target not yet deployed to destination: {}",
                    target.display()
                ),
                path: Some(target.clone()),
            });
        }
    }

    checks
}

fn check_decryption_prerequisites(args: &CommonArgs, actions: &[FileAction]) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    let explicit_key = args.age_key_file.as_deref();

    if let Some(key_path) = explicit_key {
        if !key_path.exists() {
            checks.push(DoctorCheck {
                category: "decryption_prerequisites".into(),
                severity: CheckSeverity::Error,
                message: format!(
                    "Configured age key file does not exist: {}",
                    key_path.display()
                ),
                path: Some(key_path.to_path_buf()),
            });
        } else {
            checks.push(DoctorCheck {
                category: "decryption_prerequisites".into(),
                severity: CheckSeverity::Ok,
                message: format!("Configured age key file found: {}", key_path.display()),
                path: Some(key_path.to_path_buf()),
            });
        }
    }

    let mut secrets_found = false;
    let mut sops_secrets_found = false;

    for action in actions {
        if let FileAction::Decrypt { source, .. } = action {
            secrets_found = true;
            match crypto::detect_secret_type(source) {
                Some(SecretType::Age) => {
                    match crypto::decrypt_to_memory(source, SecretType::Age, explicit_key) {
                        Ok(_) => {
                            checks.push(DoctorCheck {
                                category: "decryption_prerequisites".into(),
                                severity: CheckSeverity::Ok,
                                message: format!("Age secret decryptable: {}", source.display()),
                                path: Some(source.clone()),
                            });
                        }
                        Err(e) => {
                            checks.push(DoctorCheck {
                                category: "decryption_prerequisites".into(),
                                severity: CheckSeverity::Error,
                                message: format!(
                                    "Cannot decrypt age secret '{}': {}",
                                    source.display(),
                                    e
                                ),
                                path: Some(source.clone()),
                            });
                        }
                    }
                }
                Some(SecretType::Sops) => {
                    sops_secrets_found = true;
                    let sops_available = std::process::Command::new("sops")
                        .arg("--version")
                        .output()
                        .is_ok();
                    if !sops_available {
                        checks.push(DoctorCheck {
                            category: "decryption_prerequisites".into(),
                            severity: CheckSeverity::Error,
                            message: format!(
                                "`sops` binary not found in PATH for sops secret: {}",
                                source.display()
                            ),
                            path: Some(source.clone()),
                        });
                    } else {
                        match crypto::decrypt_to_memory(source, SecretType::Sops, explicit_key) {
                            Ok(_) => {
                                checks.push(DoctorCheck {
                                    category: "decryption_prerequisites".into(),
                                    severity: CheckSeverity::Ok,
                                    message: format!(
                                        "SOPS secret decryptable: {}",
                                        source.display()
                                    ),
                                    path: Some(source.clone()),
                                });
                            }
                            Err(e) => {
                                checks.push(DoctorCheck {
                                    category: "decryption_prerequisites".into(),
                                    severity: CheckSeverity::Error,
                                    message: format!(
                                        "Cannot decrypt SOPS secret '{}': {}",
                                        source.display(),
                                        e
                                    ),
                                    path: Some(source.clone()),
                                });
                            }
                        }
                    }
                }
                Some(SecretType::Template) => {
                    match crypto::decrypt_to_memory(source, SecretType::Template, explicit_key) {
                        Ok(_) => {
                            checks.push(DoctorCheck {
                                category: "decryption_prerequisites".into(),
                                severity: CheckSeverity::Ok,
                                message: format!("Template renderable: {}", source.display()),
                                path: Some(source.clone()),
                            });
                        }
                        Err(e) => {
                            checks.push(DoctorCheck {
                                category: "decryption_prerequisites".into(),
                                severity: CheckSeverity::Error,
                                message: format!(
                                    "Cannot render template '{}': {}",
                                    source.display(),
                                    e
                                ),
                                path: Some(source.clone()),
                            });
                        }
                    }
                }
                None => {}
            }
        }
    }

    let source_path = args.source_path();
    let sops_config = source_path.join(".sops.yaml");
    if sops_config.exists() && !sops_secrets_found {
        let sops_available = std::process::Command::new("sops")
            .arg("--version")
            .output()
            .is_ok();
        if !sops_available {
            checks.push(DoctorCheck {
                category: "decryption_prerequisites".into(),
                severity: CheckSeverity::Error,
                message: format!(
                    "`sops` binary not found in PATH but .sops.yaml exists: {}",
                    sops_config.display()
                ),
                path: Some(sops_config.clone()),
            });
        } else {
            checks.push(DoctorCheck {
                category: "decryption_prerequisites".into(),
                severity: CheckSeverity::Ok,
                message: format!(
                    "`.sops.yaml` found and `sops` CLI binary is available: {}",
                    sops_config.display()
                ),
                path: Some(sops_config.clone()),
            });
        }
    }

    if !secrets_found && !sops_config.exists() && explicit_key.is_none() {
        checks.push(DoctorCheck {
            category: "decryption_prerequisites".into(),
            severity: CheckSeverity::Ok,
            message: "No encrypted secrets or .sops.yaml found in dotfiles".into(),
            path: None,
        });
    }

    checks
}

fn find_git_root(start: &Path) -> Option<PathBuf> {
    let start_dir = if start.is_dir() {
        start
    } else {
        start.parent()?
    };
    let mut cur = start_dir
        .canonicalize()
        .unwrap_or_else(|_| start_dir.to_path_buf());
    loop {
        if cur.join(".git").exists() {
            return Some(cur);
        }
        if !cur.pop() {
            return None;
        }
    }
}

fn is_path_gitignored(git_root: &Path, target_path: &Path) -> bool {
    let norm_root = normalize_path(
        &git_root
            .canonicalize()
            .unwrap_or_else(|_| git_root.to_path_buf()),
    );
    let aligned_target = target_path
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .and_then(|cp| target_path.file_name().map(|f| normalize_path(&cp).join(f)))
        .unwrap_or_else(|| normalize_path(target_path));

    let mut builder = ignore::gitignore::GitignoreBuilder::new(&norm_root);
    let mut dirs = Vec::new();
    let mut cur = aligned_target.parent();
    while let Some(d) = cur {
        dirs.push(d.to_path_buf());
        if normalize_path(d) == norm_root {
            break;
        }
        cur = d.parent();
    }
    dirs.reverse();
    for dir in dirs {
        let gi_file = dir.join(".gitignore");
        if gi_file.is_file() {
            builder.add(gi_file);
        }
    }

    match builder.build() {
        Ok(gi) => gi
            .matched_path_or_any_parents(&aligned_target, false)
            .is_ignore(),
        Err(_) => false,
    }
}

fn is_forbidden_dotenv(path: &Path) -> bool {
    if crypto::detect_secret_type(path).is_some() {
        return false;
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if name == ".env" || name.ends_with(".env") {
        return true;
    }
    if let Some(suffix) = name.strip_prefix(".env.") {
        let lower = suffix.to_ascii_lowercase();
        return !matches!(lower.as_str(), "example" | "sample" | "template" | "dist");
    }
    false
}

fn is_forbidden_key_file(path: &Path) -> bool {
    if crypto::detect_secret_type(path).is_some() {
        return false;
    }
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".key") || lower.ends_with(".pem") {
        return true;
    }
    matches!(
        lower.as_str(),
        "id_rsa" | "id_ed25519" | "id_ecdsa" | "id_dsa" | "id_ed25519_sk" | "id_ecdsa_sk"
    )
}

/// Collect `(encrypted_path, plaintext_sibling_path)` pairs for `.age` and `.sops.*` files
/// under `roots`, excluding exact `.sops.yaml` config files whose plaintext name equals themselves.
fn collect_encrypted_counterparts(roots: &[PathBuf]) -> Vec<(PathBuf, PathBuf)> {
    let mut seen = HashSet::new();
    let mut pairs = Vec::new();

    for root in roots {
        if !root.is_dir() {
            continue;
        }
        for entry in WalkDir::new(root).into_iter().filter_entry(|e| {
            let name = e.file_name().to_str().unwrap_or_default();
            if e.file_type().is_dir() {
                name != ".git" && !is_stale_scan_ignored_dir(name)
            } else {
                true
            }
        }) {
            let Ok(entry) = entry else { continue };
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            if !matches!(
                crypto::detect_secret_type(path),
                Some(SecretType::Age | SecretType::Sops)
            ) {
                continue;
            }
            let Some(plain_name) = crypto::target_plaintext_name(path) else {
                continue;
            };
            let enc_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if plain_name == enc_name {
                continue;
            }
            let Some(parent) = path.parent() else {
                continue;
            };
            let sibling = parent.join(&plain_name);
            let norm_enc = normalize_path(path);
            if seen.insert(norm_enc) {
                pairs.push((path.to_path_buf(), sibling));
            }
        }
    }

    pairs
}

fn check_plaintext_secret_guard(args: &CommonArgs, actions: &[FileAction]) -> Vec<DoctorCheck> {
    let source_root = normalize_path(
        &args
            .source_path()
            .canonicalize()
            .unwrap_or_else(|_| args.source_path().to_path_buf()),
    );

    let roots: Vec<PathBuf> = if args.packages.is_empty() {
        vec![source_root.clone()]
    } else {
        args.packages
            .iter()
            .map(|p| source_root.join(p))
            .filter(|p| p.is_dir())
            .collect()
    };

    let mut pairs = collect_encrypted_counterparts(&roots);
    let mut seen: HashSet<PathBuf> = pairs.iter().map(|(e, _)| normalize_path(e)).collect();

    for action in actions {
        if let FileAction::Decrypt { source, .. } = action {
            if matches!(
                crypto::detect_secret_type(source),
                Some(SecretType::Age | SecretType::Sops)
            ) {
                if let (Some(plain_name), Some(parent)) =
                    (crypto::target_plaintext_name(source), source.parent())
                {
                    let enc_name = source
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or_default();
                    if plain_name != enc_name && seen.insert(normalize_path(source)) {
                        pairs.push((source.clone(), parent.join(plain_name)));
                    }
                }
            }
        }
    }

    let git_root = find_git_root(&source_root);
    let mut checks = Vec::new();
    let mut issues_found = false;

    for (encrypted, sibling) in &pairs {
        if sibling.exists() || fs::symlink_metadata(sibling).is_ok() {
            issues_found = true;
            checks.push(DoctorCheck {
                category: "secret_guard".into(),
                severity: CheckSeverity::Error,
                message: format!(
                    "Plaintext secret sibling exists in source repository alongside encrypted file: {} (encrypted: {})",
                    sibling.display(),
                    encrypted.display()
                ),
                path: Some(sibling.clone()),
            });
        }

        if let Some(ref gr) = git_root {
            if !is_path_gitignored(gr, sibling) {
                issues_found = true;
                checks.push(DoctorCheck {
                    category: "secret_guard".into(),
                    severity: CheckSeverity::Warning,
                    message: format!(
                        "Plaintext secret counterpart '{}' is not ignored by .gitignore",
                        sibling.display()
                    ),
                    path: Some(sibling.clone()),
                });
            }
        }
    }

    if !issues_found && !pairs.is_empty() {
        checks.push(DoctorCheck {
            category: "secret_guard".into(),
            severity: CheckSeverity::Ok,
            message: format!(
                "Secret guard verified across {} encrypted secret file(s)",
                pairs.len()
            ),
            path: None,
        });
    }

    checks
}

fn check_leak_scan(actions: &[FileAction]) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    let mut leaks_found = false;

    for action in actions {
        if let FileAction::Symlink { source, .. } = action {
            if let Ok(meta) = fs::metadata(source) {
                // Skip files larger than 1MB
                if meta.len() > 1_000_000 {
                    continue;
                }
            }

            if let Ok(content) = fs::read_to_string(source) {
                if let Some(desc) = scan_content_for_leaks(&content) {
                    leaks_found = true;
                    checks.push(DoctorCheck {
                        category: "leak_scan".into(),
                        severity: CheckSeverity::Warning,
                        message: format!(
                            "Potential credential leak detected in unencrypted dotfile '{}': {}",
                            source.display(),
                            desc
                        ),
                        path: Some(source.clone()),
                    });
                }
            }
        }
    }

    if !leaks_found {
        checks.push(DoctorCheck {
            category: "leak_scan".into(),
            severity: CheckSeverity::Ok,
            message: "No credential leaks detected in unencrypted dotfiles".into(),
            path: None,
        });
    }

    checks
}

fn scan_content_for_leaks(content: &str) -> Option<&'static str> {
    if content.contains("-----BEGIN OPENSSH PRIVATE KEY-----") {
        return Some("OpenSSH private key");
    }
    if content.contains("-----BEGIN RSA PRIVATE KEY-----") {
        return Some("RSA private key");
    }
    if content.contains("-----BEGIN DSA PRIVATE KEY-----") {
        return Some("DSA private key");
    }
    if content.contains("-----BEGIN EC PRIVATE KEY-----") {
        return Some("EC private key");
    }
    if content.contains("-----BEGIN PRIVATE KEY-----") {
        return Some("PKCS#8 private key");
    }
    if content.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
        return Some("PGP private key");
    }
    if content.contains("AGE-SECRET-KEY-1") {
        return Some("unencrypted age private key");
    }
    if content.contains("ghp_") {
        return Some("GitHub personal access token");
    }
    if content.contains("gho_") {
        return Some("GitHub OAuth token");
    }
    if content.contains("github_pat_") {
        return Some("GitHub fine-grained personal access token");
    }
    if content.contains("glpat-") {
        return Some("GitLab personal access token");
    }
    if content.contains("xoxb-") || content.contains("xoxp-") || content.contains("xoxa-") {
        return Some("Slack API token");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_forbidden_key_file_cases() {
        for forbidden in [
            "server.key",
            "certs/TLS.KEY",
            "private.pem",
            "certs/CERT.PEM",
            ".ssh/id_rsa",
            ".ssh/id_ed25519",
            ".ssh/id_ecdsa",
            ".ssh/id_dsa",
            ".ssh/id_ed25519_sk",
            ".ssh/id_ecdsa_sk",
        ] {
            assert!(
                is_forbidden_key_file(Path::new(forbidden)),
                "expected '{forbidden}' to be forbidden"
            );
        }

        for allowed in [
            ".ssh/id_rsa.pub",
            ".ssh/id_ed25519.pub",
            ".ssh/id_ed25519.age",
            "certs/server.key.age",
            "certs/server.key.example",
            "certs/private.pem.sops.yaml",
            "docs/id_rsa_guide.md",
            "README.md",
        ] {
            assert!(
                !is_forbidden_key_file(Path::new(allowed)),
                "expected '{allowed}' to be allowed"
            );
        }
    }
}
