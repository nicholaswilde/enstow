use crate::error::EnstowError;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretType {
    Age,
    Sops,
}

pub fn detect_secret_type(path: &Path) -> Option<SecretType> {
    let name = path.file_name()?.to_str()?;
    if name.ends_with(".age") {
        Some(SecretType::Age)
    } else if name.contains(".sops.") || name == ".sops.yaml" {
        Some(SecretType::Sops)
    } else {
        None
    }
}

pub fn target_plaintext_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    if let Some(stripped) = name.strip_suffix(".age") {
        Some(stripped.to_string())
    } else if let Some(stripped) = name.strip_suffix(".sops.yaml") {
        Some(format!("{stripped}.yaml"))
    } else if let Some(stripped) = name.strip_suffix(".sops.json") {
        Some(format!("{stripped}.json"))
    } else {
        Some(name.replace(".sops.", "."))
    }
}

pub fn decrypt_to_memory(
    path: &Path,
    secret_type: SecretType,
    age_key_file: Option<&Path>,
) -> Result<Vec<u8>, EnstowError> {
    match secret_type {
        SecretType::Age => decrypt_age(path, age_key_file),
        SecretType::Sops => decrypt_sops(path),
    }
}

pub fn decrypt_age(path: &Path, age_key_file: Option<&Path>) -> Result<Vec<u8>, EnstowError> {
    let key_paths = get_age_key_paths(age_key_file);
    if key_paths.is_empty() {
        return Err(EnstowError::Decryption {
            path: path.to_path_buf(),
            message:
                "No age key file found. Set SOPS_AGE_KEY_FILE or ensure default age key exists."
                    .into(),
        });
    }

    let mut identities = Vec::new();
    for kp in &key_paths {
        if kp.exists() {
            if let Ok(identity_file) =
                age::IdentityFile::from_file(kp.to_string_lossy().into_owned())
            {
                if let Ok(mut ids) = identity_file.into_identities() {
                    identities.append(&mut ids);
                }
            }
        }
    }

    if identities.is_empty() {
        return Err(EnstowError::Decryption {
            path: path.to_path_buf(),
            message: format!("Could not load any age identities from {:?}", key_paths),
        });
    }

    let file = File::open(path).map_err(|e| EnstowError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let decryptor = age::Decryptor::new(file).map_err(|e| EnstowError::Decryption {
        path: path.to_path_buf(),
        message: format!("Failed to initialize age decryptor: {e}"),
    })?;

    let id_refs: Vec<&dyn age::Identity> = identities
        .iter()
        .map(|id| -> &dyn age::Identity { &**id })
        .collect();

    let mut reader =
        decryptor
            .decrypt(id_refs.into_iter())
            .map_err(|e| EnstowError::Decryption {
                path: path.to_path_buf(),
                message: format!("Decryption failed: {e}"),
            })?;

    let mut plaintext = Vec::new();
    reader
        .read_to_end(&mut plaintext)
        .map_err(|e| EnstowError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

    Ok(plaintext)
}

pub fn decrypt_sops(path: &Path) -> Result<Vec<u8>, EnstowError> {
    info!("Decrypting sops file: {}", path.display());
    let output = Command::new("sops")
        .arg("-d")
        .arg(path)
        .output()
        .map_err(|e| EnstowError::Decryption {
            path: path.to_path_buf(),
            message: format!("Failed to execute `sops`: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(EnstowError::Decryption {
            path: path.to_path_buf(),
            message: format!("sops decryption failed: {stderr}"),
        });
    }

    Ok(output.stdout)
}

pub fn write_secure_file(path: &Path, content: &[u8], force: bool) -> Result<(), EnstowError> {
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !force {
            return Err(EnstowError::Collision {
                path: path.to_path_buf(),
            });
        }
        if meta.file_type().is_dir() {
            std::fs::remove_dir_all(path).map_err(|e| EnstowError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;
        } else {
            std::fs::remove_file(path).map_err(|e| EnstowError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;
        }
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| EnstowError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| EnstowError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;

        file.write_all(content).map_err(|e| EnstowError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, content).map_err(|e| EnstowError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
    }

    Ok(())
}

fn get_age_key_paths(explicit_key: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(explicit) = explicit_key {
        paths.push(explicit.to_path_buf());
    }
    if let Ok(key_file) = std::env::var("SOPS_AGE_KEY_FILE") {
        let p = PathBuf::from(key_file);
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join(".config/sops/age/keys.txt");
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    paths
}
