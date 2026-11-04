use crate::error::EnstowError;
use age::secrecy::SecretString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use tracing::info;
use zeroize::Zeroize;

static SESSION_PASSPHRASE: Mutex<Option<SecretString>> = Mutex::new(None);

pub fn clear_session_passphrase() {
    if let Ok(mut lock) = SESSION_PASSPHRASE.lock() {
        *lock = None;
    }
}

fn get_passphrase_for_encrypt() -> Result<SecretString, EnstowError> {
    if let Ok(pass) = std::env::var("ENSTOW_PASSPHRASE") {
        if !pass.is_empty() {
            let mut pass = pass;
            let secret = SecretString::from(pass.clone());
            pass.zeroize();
            return Ok(secret);
        }
    }

    if let Ok(lock) = SESSION_PASSPHRASE.lock() {
        if let Some(ref cached) = *lock {
            return Ok(cached.clone());
        }
    }

    let p1 = rpassword::prompt_password("Enter passphrase: ").map_err(|e| {
        EnstowError::Config(format!(
            "Passphrase required: set ENSTOW_PASSPHRASE or run in an interactive terminal ({e})"
        ))
    })?;
    let p2 = rpassword::prompt_password("Confirm passphrase: ").map_err(|e| {
        EnstowError::Config(format!(
            "Passphrase required: set ENSTOW_PASSPHRASE or run in an interactive terminal ({e})"
        ))
    })?;

    if p1 != p2 {
        let mut p1 = p1;
        let mut p2 = p2;
        p1.zeroize();
        p2.zeroize();
        return Err(EnstowError::Config("Passphrases do not match".into()));
    }

    let mut p1 = p1;
    let mut p2 = p2;
    p2.zeroize();
    let secret = SecretString::from(p1.clone());
    p1.zeroize();

    if let Ok(mut lock) = SESSION_PASSPHRASE.lock() {
        *lock = Some(secret.clone());
    }

    Ok(secret)
}

fn get_passphrase_for_decrypt(path: &Path) -> Result<SecretString, EnstowError> {
    if let Ok(pass) = std::env::var("ENSTOW_PASSPHRASE") {
        if !pass.is_empty() {
            let mut pass = pass;
            let secret = SecretString::from(pass.clone());
            pass.zeroize();
            return Ok(secret);
        }
    }

    if let Ok(lock) = SESSION_PASSPHRASE.lock() {
        if let Some(ref cached) = *lock {
            return Ok(cached.clone());
        }
    }

    let prompt = format!("Enter passphrase for {}: ", path.display());
    let pass = rpassword::prompt_password(&prompt).map_err(|e| EnstowError::Decryption {
        path: path.to_path_buf(),
        message: format!(
            "Passphrase required: set ENSTOW_PASSPHRASE or run in an interactive terminal ({e})"
        ),
    })?;

    let mut pass = pass;
    let secret = SecretString::from(pass.clone());
    pass.zeroize();
    Ok(secret)
}

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
    let file = File::open(path).map_err(|e| EnstowError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let decryptor =
        age::Decryptor::new_buffered(age::armor::ArmoredReader::new(file)).map_err(|e| {
            EnstowError::Decryption {
                path: path.to_path_buf(),
                message: format!("Failed to initialize age decryptor: {e}"),
            }
        })?;

    if decryptor.is_scrypt() {
        let passphrase = get_passphrase_for_decrypt(path)?;
        let identity = age::scrypt::Identity::new(passphrase.clone());
        match decryptor.decrypt(std::iter::once(&identity as &dyn age::Identity)) {
            Ok(mut reader) => {
                let mut plaintext = Vec::new();
                reader
                    .read_to_end(&mut plaintext)
                    .map_err(|e| EnstowError::Io {
                        path: path.to_path_buf(),
                        source: e,
                    })?;
                if let Ok(mut lock) = SESSION_PASSPHRASE.lock() {
                    *lock = Some(passphrase);
                }
                return Ok(plaintext);
            }
            Err(e) => {
                clear_session_passphrase();
                return Err(EnstowError::Decryption {
                    path: path.to_path_buf(),
                    message: format!("Decryption failed: {e}"),
                });
            }
        }
    }

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
            } else if let Ok(file) = File::open(kp) {
                if let Ok(ssh_id) = age::ssh::Identity::from_buffer(
                    std::io::BufReader::new(file),
                    Some(kp.to_string_lossy().into_owned()),
                ) {
                    match ssh_id {
                        age::ssh::Identity::Unsupported(_) => {}
                        id => identities.push(Box::new(id.with_callbacks(SshCallbacks))),
                    }
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

#[derive(Clone)]
struct SshCallbacks;

impl age::Callbacks for SshCallbacks {
    fn display_message(&self, _message: &str) {}
    fn confirm(&self, _message: &str, _yes_string: &str, _no_string: Option<&str>) -> Option<bool> {
        None
    }
    fn request_public_string(&self, _description: &str) -> Option<String> {
        None
    }
    fn request_passphrase(&self, description: &str) -> Option<age::secrecy::SecretString> {
        if let Ok(pass) = std::env::var("ENSTOW_SSH_PASSPHRASE")
            .or_else(|_| std::env::var("SSH_PASSPHRASE"))
            .or_else(|_| std::env::var("ENSTOW_PASSPHRASE"))
        {
            if !pass.is_empty() {
                return Some(age::secrecy::SecretString::from(pass));
            }
        }
        rpassword::prompt_password(format!("Enter passphrase for SSH key ({description}): "))
            .ok()
            .map(age::secrecy::SecretString::from)
    }
}

fn load_recipients_from_str(r: &str) -> Result<Vec<Box<dyn age::Recipient + Send>>, EnstowError> {
    use std::str::FromStr;
    let trimmed = r.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    // 1. Try parsing directly as an age recipient
    if let Ok(pk) = age::x25519::Recipient::from_str(trimmed) {
        return Ok(vec![Box::new(pk)]);
    }

    // 2. Try parsing directly as an SSH recipient
    if let Ok(pk) = age::ssh::Recipient::from_str(trimmed) {
        return Ok(vec![Box::new(pk)]);
    }

    // 3. Check if r is a file path
    let file_path = if trimmed.starts_with("~/") {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join(&trimmed[2..]))
            .unwrap_or_else(|| PathBuf::from(trimmed))
    } else {
        PathBuf::from(trimmed)
    };

    if file_path.is_file() {
        return load_recipients_from_file(&file_path);
    }

    Err(EnstowError::Config(format!(
        "Failed to parse recipient '{trimmed}': not a valid age or SSH public key (or recipient file)"
    )))
}

fn load_recipients_from_file(
    path: &Path,
) -> Result<Vec<Box<dyn age::Recipient + Send>>, EnstowError> {
    use std::str::FromStr;

    // 1. Try as age IdentityFile
    if let Ok(id_file) = age::IdentityFile::from_file(path.to_string_lossy().into_owned()) {
        if let Ok(recips) = id_file.to_recipients() {
            if !recips.is_empty() {
                return Ok(recips);
            }
        }
    }

    // 2. If a corresponding .pub file exists, try reading public key lines from it
    let pub_path = PathBuf::from(format!("{}.pub", path.display()));
    if pub_path.is_file() {
        if let Ok(content) = std::fs::read_to_string(&pub_path) {
            let mut list: Vec<Box<dyn age::Recipient + Send>> = Vec::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Ok(pk) = age::ssh::Recipient::from_str(line) {
                    list.push(Box::new(pk));
                } else if let Ok(pk) = age::x25519::Recipient::from_str(line) {
                    list.push(Box::new(pk));
                }
            }
            if !list.is_empty() {
                return Ok(list);
            }
        }
    }

    // 3. Try parsing as SSH private key identity and convert to recipient
    if let Ok(file) = File::open(path) {
        if let Ok(ssh_id) = age::ssh::Identity::from_buffer(
            std::io::BufReader::new(file),
            Some(path.to_string_lossy().into_owned()),
        ) {
            if let Ok(ssh_recip) = age::ssh::Recipient::try_from(ssh_id) {
                return Ok(vec![Box::new(ssh_recip)]);
            }
        }
    }

    // 4. Try reading path directly line-by-line (e.g. .pub file or recipients list)
    if let Ok(content) = std::fs::read_to_string(path) {
        let mut list: Vec<Box<dyn age::Recipient + Send>> = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Ok(pk) = age::ssh::Recipient::from_str(line) {
                list.push(Box::new(pk));
            } else if let Ok(pk) = age::x25519::Recipient::from_str(line) {
                list.push(Box::new(pk));
            }
        }
        if !list.is_empty() {
            return Ok(list);
        }
    }

    Err(EnstowError::Config(format!(
        "No valid age or SSH recipients could be extracted from '{}'",
        path.display()
    )))
}

pub fn encrypt_file_age_with_passphrase(
    input_path: &Path,
    output_path: &Path,
    passphrase: SecretString,
) -> Result<(), EnstowError> {
    use std::io::Write;

    let plaintext = std::fs::read(input_path).map_err(|e| EnstowError::Io {
        path: input_path.to_path_buf(),
        source: e,
    })?;

    let encryptor = age::Encryptor::with_user_passphrase(passphrase);

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

pub fn resolve_age_recipients(
    recipients: &[String],
    age_key_file: Option<&Path>,
) -> Result<Vec<Box<dyn age::Recipient + Send>>, EnstowError> {
    let mut recipient_list: Vec<Box<dyn age::Recipient + Send>> = Vec::new();

    // 1. Explicit recipient strings
    for r in recipients {
        let parsed = load_recipients_from_str(r)?;
        recipient_list.extend(parsed);
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
                let parsed = load_recipients_from_str(r)?;
                recipient_list.extend(parsed);
            }
        }
    }

    // 3. Fallback to extracting public keys from key files
    if recipient_list.is_empty() {
        let key_paths = get_age_key_paths(age_key_file);
        for kp in &key_paths {
            if kp.exists() {
                if let Ok(recips) = load_recipients_from_file(kp) {
                    if !recips.is_empty() {
                        recipient_list.extend(recips);
                        break;
                    }
                }
            }
        }
    }

    if recipient_list.is_empty() {
        return Err(EnstowError::Config(
            "No age or SSH recipients found. Provide --recipient, set ENSTOW_RECIPIENTS (or SOPS_AGE_RECIPIENTS), or ensure an age or SSH key file exists.".into(),
        ));
    }

    Ok(recipient_list)
}

pub fn encrypt_bytes_age_with_recipients(
    plaintext: &[u8],
    output_path: &Path,
    recipient_list: &[Box<dyn age::Recipient + Send>],
) -> Result<(), EnstowError> {
    use std::io::Write;

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

    writer.write_all(plaintext).map_err(|e| EnstowError::Io {
        path: output_path.to_path_buf(),
        source: e,
    })?;

    writer.finish().map_err(|e| EnstowError::Io {
        path: output_path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

pub fn rekey_file_age_with_recipients(
    path: &Path,
    recipient_list: &[Box<dyn age::Recipient + Send>],
    age_key_file: Option<&Path>,
) -> Result<(), EnstowError> {
    let plaintext = decrypt_age(path, age_key_file)?;

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let temp_file = tempfile::Builder::new()
        .prefix(".enstow-rekey-")
        .suffix(".age.tmp")
        .tempfile_in(parent)
        .map_err(|e| EnstowError::Io {
            path: parent.to_path_buf(),
            source: e,
        })?;

    let temp_path = temp_file.into_temp_path();

    encrypt_bytes_age_with_recipients(&plaintext, &temp_path, recipient_list)?;

    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&temp_path, meta.permissions());
    }

    temp_path.persist(path).map_err(|e| EnstowError::Io {
        path: path.to_path_buf(),
        source: e.error,
    })?;

    Ok(())
}

pub fn rekey_packages(
    source_root: &Path,
    packages: &[String],
    ignore: &[String],
    recipients: &[String],
    age_key_file: Option<&Path>,
    dry_run: bool,
) -> Result<Vec<PathBuf>, EnstowError> {
    let recipient_list = resolve_age_recipients(recipients, age_key_file)?;
    let age_files = crate::stow::find_age_secrets(source_root, packages, ignore)?;

    if dry_run {
        for file in &age_files {
            println!("[dry-run] REKEY {}", file.display());
        }
        return Ok(age_files);
    }

    for file in &age_files {
        rekey_file_age_with_recipients(file, &recipient_list, age_key_file)?;
        println!("Rekeyed {}", file.display());
    }

    Ok(age_files)
}

pub fn encrypt_file_age(
    input_path: &Path,
    output_path: &Path,
    recipients: &[String],
    age_key_file: Option<&Path>,
    passphrase: bool,
) -> Result<(), EnstowError> {
    if passphrase {
        let secret = get_passphrase_for_encrypt()?;
        return encrypt_file_age_with_passphrase(input_path, output_path, secret);
    }

    let recipient_list = resolve_age_recipients(recipients, age_key_file)?;

    let plaintext = std::fs::read(input_path).map_err(|e| EnstowError::Io {
        path: input_path.to_path_buf(),
        source: e,
    })?;

    encrypt_bytes_age_with_recipients(&plaintext, output_path, &recipient_list)
}

pub fn write_secure_file(path: &Path, content: &[u8], force: bool) -> Result<(), EnstowError> {
    write_secure_file_with_mode(path, content, force, 0o600)
}

pub fn write_secure_file_with_mode(
    path: &Path,
    content: &[u8],
    force: bool,
    mode: u32,
) -> Result<(), EnstowError> {
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
        use std::os::unix::fs::PermissionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .map_err(|e| EnstowError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;

        file.write_all(content).map_err(|e| EnstowError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }

    #[cfg(not(unix))]
    {
        let _ = mode;
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

    let is_scrypt = {
        if let Ok(f) = File::open(file) {
            age::Decryptor::new_buffered(age::armor::ArmoredReader::new(f))
                .map(|d| d.is_scrypt())
                .unwrap_or(false)
        } else {
            false
        }
    };

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
    encrypt_file_age(&temp_path, &temp_out, recipients, age_key_file, is_scrypt)?;
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
    if let Ok(ssh_key) = std::env::var("ENSTOW_SSH_KEY_FILE") {
        let p = PathBuf::from(ssh_key);
        if !paths.contains(&p) {
            paths.push(p);
        }
    }
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(&home)
            .join(".config")
            .join("sops")
            .join("age")
            .join("keys.txt");
        if !paths.contains(&p) {
            paths.push(p);
        }
        let ed25519 = PathBuf::from(&home).join(".ssh").join("id_ed25519");
        if !paths.contains(&ed25519) {
            paths.push(ed25519);
        }
        let rsa = PathBuf::from(&home).join(".ssh").join("id_rsa");
        if !paths.contains(&rsa) {
            paths.push(rsa);
        }
    }
    paths
}
