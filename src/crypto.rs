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
                "No age key file found. Set ENSTOW_AGE_KEY_FILE (or SOPS_AGE_KEY_FILE) or ensure default age key exists."
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

pub fn encrypt_file_age(
    input_path: &Path,
    output_path: &Path,
    recipients: &[String],
    age_key_file: Option<&Path>,
) -> Result<(), EnstowError> {
    use std::io::Write;
    use std::str::FromStr;

    let mut recipient_list: Vec<Box<dyn age::Recipient + Send>> = Vec::new();

    // 1. Explicit recipient strings
    for r in recipients {
        let pk =
            age::x25519::Recipient::from_str(r).map_err(|e| EnstowError::Config(e.to_string()))?;
        recipient_list.push(Box::new(pk));
    }

    // 2. ENSTOW_RECIPIENTS / SOPS_AGE_RECIPIENTS env var if none provided
    if recipient_list.is_empty() {
        let env_recips =
            std::env::var("ENSTOW_RECIPIENTS").or_else(|_| std::env::var("SOPS_AGE_RECIPIENTS"));
        if let Ok(recips_val) = env_recips {
            for r in recips_val
                .split([',', '\n'])
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
            {
                let pk = age::x25519::Recipient::from_str(r)
                    .map_err(|e| EnstowError::Config(e.to_string()))?;
                recipient_list.push(Box::new(pk));
            }
        }
    }

    // 3. Fallback to extracting public keys from key files
    if recipient_list.is_empty() {
        let key_paths = get_age_key_paths(age_key_file);
        for kp in key_paths {
            if kp.exists() {
                if let Ok(id_file) = age::IdentityFile::from_file(kp.to_string_lossy().into_owned())
                {
                    if let Ok(recips) = id_file.to_recipients() {
                        recipient_list.extend(recips);
                    }
                }
            }
        }
    }

    if recipient_list.is_empty() {
        return Err(EnstowError::Config(
            "No age recipients found. Provide --recipient, set ENSTOW_RECIPIENTS (or SOPS_AGE_RECIPIENTS), or ensure an age key file exists.".into(),
        ));
    }

    let plaintext = std::fs::read(input_path).map_err(|e| EnstowError::Io {
        path: input_path.to_path_buf(),
        source: e,
    })?;

    let recip_refs: Vec<&dyn age::Recipient> = recipient_list
        .iter()
        .map(|r| &**r as &dyn age::Recipient)
        .collect();

    let encryptor = age::Encryptor::with_recipients(recip_refs.into_iter())
        .map_err(|e| EnstowError::Config(format!("Failed to initialize encryptor: {e}")))?;

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| EnstowError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }

    let mut out_file = std::fs::File::create(output_path).map_err(|e| EnstowError::Io {
        path: output_path.to_path_buf(),
        source: e,
    })?;

    let mut writer = encryptor
        .wrap_output(&mut out_file)
        .map_err(|e| EnstowError::Config(format!("Failed to wrap encryptor output: {e}")))?;

    writer.write_all(&plaintext).map_err(|e| EnstowError::Io {
        path: output_path.to_path_buf(),
        source: e,
    })?;

    writer.finish().map_err(|e| EnstowError::Io {
        path: output_path.to_path_buf(),
        source: e,
    })?;

    Ok(())
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

pub fn edit_file_age(
    file: &Path,
    recipients: &[String],
    age_key_file: Option<&Path>,
    editor_override: Option<&str>,
) -> Result<bool, EnstowError> {
    if !file.exists() {
        return Err(EnstowError::Io {
            path: file.to_path_buf(),
            source: std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Secret file not found: {}", file.display()),
            ),
        });
    }

    if detect_secret_type(file) != Some(SecretType::Age) {
        return Err(EnstowError::Config(format!(
            "File is not an age encrypted secret: {}",
            file.display()
        )));
    }

    let plaintext = decrypt_age(file, age_key_file)?;

    let temp_dir = tempfile::Builder::new()
        .prefix(".enstow-edit-")
        .tempdir()
        .map_err(|e| EnstowError::Io {
            path: PathBuf::from("tempdir"),
            source: e,
        })?;

    let target_name = target_plaintext_name(file).unwrap_or_else(|| "secret".into());
    let temp_path = temp_dir.path().join(&target_name);

    #[cfg(unix)]
    {
        use std::fs::OpenOptions;
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_path)
            .map_err(|e| EnstowError::Io {
                path: temp_path.clone(),
                source: e,
            })?;
        f.write_all(&plaintext).map_err(|e| EnstowError::Io {
            path: temp_path.clone(),
            source: e,
        })?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(&temp_path, &plaintext).map_err(|e| EnstowError::Io {
            path: temp_path.clone(),
            source: e,
        })?;
    }

    let editor = editor_override
        .map(String::from)
        .or_else(|| {
            std::env::var("ENSTOW_EDITOR")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .or_else(|| {
            std::env::var("VISUAL")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "notepad".to_string()
            } else {
                "vi".to_string()
            }
        });

    let status = {
        let editor_path = Path::new(&editor);
        if editor_path.is_file() {
            Command::new(editor_path)
                .arg(&temp_path)
                .status()
                .map_err(|e| EnstowError::Config(format!("Failed to run editor '{editor}': {e}")))?
        } else {
            let mut parts = editor.split_whitespace();
            let prog = parts
                .next()
                .unwrap_or(if cfg!(windows) { "notepad" } else { "vi" });
            let args: Vec<&str> = parts.collect();
            Command::new(prog)
                .args(&args)
                .arg(&temp_path)
                .status()
                .map_err(|e| EnstowError::Config(format!("Failed to run editor '{editor}': {e}")))?
        }
    };

    if !status.success() {
        return Err(EnstowError::Config(format!(
            "Editor '{editor}' exited with status: {}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "terminated by signal".into())
        )));
    }

    let new_plaintext = std::fs::read(&temp_path).map_err(|e| EnstowError::Io {
        path: temp_path.clone(),
        source: e,
    })?;

    if new_plaintext == plaintext {
        info!("No changes detected in secret file: {}", file.display());
        return Ok(false);
    }

    let temp_out = file.with_extension("age.tmp");
    encrypt_file_age(&temp_path, &temp_out, recipients, age_key_file)?;
    if let Ok(meta) = std::fs::metadata(file) {
        let _ = std::fs::set_permissions(&temp_out, meta.permissions());
    }
    std::fs::rename(&temp_out, file).map_err(|e| EnstowError::Io {
        path: file.to_path_buf(),
        source: e,
    })?;

    info!("Successfully re-encrypted secret file: {}", file.display());
    Ok(true)
}

fn get_age_key_paths(explicit_key: Option<&Path>) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(explicit) = explicit_key {
        paths.push(explicit.to_path_buf());
    }
    if let Ok(key_file) = std::env::var("ENSTOW_AGE_KEY_FILE") {
        let p = PathBuf::from(key_file);
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    if let Ok(key_file) = std::env::var("SOPS_AGE_KEY_FILE") {
        let p = PathBuf::from(key_file);
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home)
            .join(".config")
            .join("sops")
            .join("age")
            .join("keys.txt");
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    paths
}
