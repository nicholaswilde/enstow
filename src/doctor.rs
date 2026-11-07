use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::cli::CommonArgs;
use crate::config::PermissionsConfig;
use crate::crypto::{self, SecretType};
use crate::error::EnstowError;
use crate::stow::{is_stale_scan_ignored_dir, normalize_path, plan_prune, plan_stow, FileAction};

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

    checks.extend(check_package_collisions(&actions));
    checks.extend(check_symlink_health(args, &actions)?);
    checks.extend(check_secret_permissions(
        &actions,
        &args.target_path(),
        permissions,
    ));
    checks.extend(check_decryption_prerequisites(args, &actions));
    checks.extend(check_leak_scan(&actions));

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

fn check_symlink_health(
    args: &CommonArgs,
    actions: &[FileAction],
) -> Result<Vec<DoctorCheck>, EnstowError> {
    let mut checks = Vec::new();
    let target_path = args.target_path();

    if !target_path.exists() {
        checks.push(DoctorCheck {
            category: "symlink_health".into(),
            severity: CheckSeverity::Ok,
            message: format!(
                "Target destination directory does not exist yet: {}",
                target_path.display()
            ),
            path: Some(target_path),
        });
        return Ok(checks);
    }

    let target_canonical = target_path
        .canonicalize()
        .unwrap_or_else(|_| target_path.clone());

    let mut reported_paths = HashSet::new();

    // 1. Scan target directory for dangling symlinks
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
        let Ok(entry) = entry else { continue };
        if entry.path_is_symlink() {
            let symlink_path = entry.path();
            if let Ok(dest) = fs::read_link(symlink_path) {
                let full_dest = if dest.is_relative() {
                    match symlink_path.parent() {
                        Some(parent) => parent.join(&dest),
                        None => dest,
                    }
                } else {
                    dest
                };

                // Check if destination exists
                if !full_dest.exists() {
                    reported_paths.insert(symlink_path.to_path_buf());
                    checks.push(DoctorCheck {
                        category: "symlink_health".into(),
                        severity: CheckSeverity::Error,
                        message: format!(
                            "Dangling symlink pointing to nonexistent path: {} -> {}",
                            symlink_path.display(),
                            full_dest.display()
                        ),
                        path: Some(symlink_path.to_path_buf()),
                    });
                }
            }
        }
    }

    // 2. Scan for stale symlinks belonging to managed dotfiles no longer active
    if let Ok(stale_actions) = plan_prune(args) {
        for stale in stale_actions {
            let target = stale.target().to_path_buf();
            if !reported_paths.contains(&target) {
                reported_paths.insert(target.clone());
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

    // 3. Verify active symlink actions
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
    target_root: &Path,
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
                    let expected_mode = permissions
                        .map(|p| p.resolve_mode(target, Some(source), Some(target_root)))
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
                let _ = (source, permissions, target_root);
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
