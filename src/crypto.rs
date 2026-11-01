use crate::error::EnstowError;
use std::path::Path;
use tracing::info;

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

#[allow(dead_code)]
pub fn decrypt_to_memory(path: &Path, secret_type: SecretType) -> Result<Vec<u8>, EnstowError> {
    match secret_type {
        SecretType::Age => {
            info!("Decrypting age file: {}", path.display());
            // Stub for age decryption logic
            Ok(Vec::new())
        }
        SecretType::Sops => {
            info!("Decrypting sops file: {}", path.display());
            // Stub for sops decryption logic
            Ok(Vec::new())
        }
    }
}
