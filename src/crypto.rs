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
    Template,
}

pub fn detect_secret_type(path: &Path) -> Option<SecretType> {
    let name = path.file_name()?.to_str()?;
    if name.ends_with(".age") {
        Some(SecretType::Age)
    } else if name.contains(".sops.") || name == ".sops.yaml" {
        Some(SecretType::Sops)
    } else if name.ends_with(".tmpl") {
        Some(SecretType::Template)
    } else {
        None
    }
}

pub fn target_plaintext_name(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    if let Some(stripped) = name.strip_suffix(".age") {
        Some(stripped.to_string())
    } else if let Some(stripped) = name.strip_suffix(".tmpl") {
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
        SecretType::Template => render_template_file(path, age_key_file),
    }
}

#[derive(Debug, Clone, Default)]
pub struct TemplateContext {
    pub os: String,
    pub arch: String,
    pub hostname: String,
    pub profile: String,
    pub env: std::collections::BTreeMap<String, String>,
    pub secrets: std::collections::BTreeMap<String, String>,
}

pub fn render_template(template: &str, ctx: &TemplateContext) -> Result<String, EnstowError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after_open = &rest[start + 2..];
        let Some(end) = after_open.find("}}") else {
            return Err(EnstowError::Config(
                "Unclosed template expression '{{'".into(),
            ));
        };

        let expr = after_open[..end].trim();
        let val = match expr {
            "os" => ctx.os.as_str(),
            "arch" => ctx.arch.as_str(),
            "hostname" => ctx.hostname.as_str(),
            "profile" => ctx.profile.as_str(),
            _ if expr.starts_with("env.") => {
                let key = expr["env.".len()..].trim();
                ctx.env.get(key).map(String::as_str).ok_or_else(|| {
                    EnstowError::Config(format!(
                        "Undefined environment variable '{key}' in template"
                    ))
                })?
            }
            _ if expr.starts_with("secrets.") => {
                let key = expr["secrets.".len()..].trim();
                ctx.secrets.get(key).map(String::as_str).ok_or_else(|| {
                    EnstowError::Config(format!("Undefined secret '{key}' in template"))
                })?
            }
            _ => {
                return Err(EnstowError::Config(format!(
                    "Unknown template variable '{expr}'"
                )))
            }
        };

        out.push_str(val);
        rest = &after_open[end + 2..];
    }

    out.push_str(rest);
    Ok(out)
}

fn insert_secret_kv(
    map: &mut std::collections::BTreeMap<String, String>,
    stem: &str,
    key: String,
    val: String,
) {
    if !stem.is_empty() && stem != "secrets" {
        map.insert(format!("{stem}.{key}"), val.clone());
    }
    map.insert(key, val);
}

fn flatten_json_value(
    prefix: &str,
    stem: &str,
    val: &serde_json::Value,
    map: &mut std::collections::BTreeMap<String, String>,
) {
    match val {
        serde_json::Value::Object(obj) => {
            for (k, v) in obj {
                let next = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                flatten_json_value(&next, stem, v, map);
            }
        }
        serde_json::Value::String(s) => insert_secret_kv(map, stem, prefix.to_string(), s.clone()),
        serde_json::Value::Number(n) => {
            insert_secret_kv(map, stem, prefix.to_string(), n.to_string())
        }
        serde_json::Value::Bool(b) => {
            insert_secret_kv(map, stem, prefix.to_string(), b.to_string())
        }
        _ => {}
    }
}

fn parse_secret_kv_text(
    file_name: &str,
    text: &str,
    map: &mut std::collections::BTreeMap<String, String>,
) {
    let base = file_name
        .strip_suffix(".age")
        .unwrap_or(file_name)
        .replace(".sops.", ".");
    let stem = base
        .trim_start_matches('.')
        .strip_suffix(".env")
        .or_else(|| base.trim_start_matches('.').strip_suffix(".toml"))
        .or_else(|| base.trim_start_matches('.').strip_suffix(".yaml"))
        .or_else(|| base.trim_start_matches('.').strip_suffix(".yml"))
        .or_else(|| base.trim_start_matches('.').strip_suffix(".json"))
        .unwrap_or_else(|| base.trim_start_matches('.'))
        .trim_start_matches("secrets.");

    if base.ends_with(".json") {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
            flatten_json_value("", stem, &v, map);
            return;
        }
    } else if base.ends_with(".toml") {
        if let Ok(t) = toml::from_str::<toml::Value>(text) {
            if let Ok(v) = serde_json::to_value(t) {
                flatten_json_value("", stem, &v, map);
                return;
            }
        }
    } else if base.ends_with(".yaml") || base.ends_with(".yml") {
        if let Ok(y) = serde_yaml_ng::from_str::<serde_json::Value>(text) {
            flatten_json_value("", stem, &y, map);
            return;
        }
    }

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let stripped = trimmed.strip_prefix("export ").unwrap_or(trimmed).trim();
        if let Some((k, v)) = stripped.split_once('=') {
            let key = k.trim().to_string();
            let raw_val = v.trim();
            let val = raw_val
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| {
                    raw_val
                        .strip_prefix('\'')
                        .and_then(|s| s.strip_suffix('\''))
                })
                .unwrap_or(raw_val)
                .to_string();
            if !key.is_empty() {
                insert_secret_kv(map, stem, key, val);
            }
        }
    }
}

fn load_secret_stores_for_template(
    tmpl_path: &Path,
    age_key_file: Option<&Path>,
) -> Result<std::collections::BTreeMap<String, String>, EnstowError> {
    let mut dirs = Vec::new();
    let mut cur = tmpl_path.parent();
    for _ in 0..3 {
        if let Some(d) = cur {
            dirs.push(d.to_path_buf());
            cur = d.parent();
        } else {
            break;
        }
    }
    dirs.reverse();

    let mut secrets = std::collections::BTreeMap::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut paths: Vec<PathBuf> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        paths.sort();

        for path in paths {
            match detect_secret_type(&path) {
                Some(SecretType::Age) | Some(SecretType::Sops) => {
                    let st = detect_secret_type(&path).unwrap();
                    let mut decrypted = decrypt_to_memory(&path, st, age_key_file)?;
                    if let Ok(mut text) = String::from_utf8(decrypted.clone()) {
                        let fname = path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or_default();
                        parse_secret_kv_text(fname, &text, &mut secrets);
                        text.zeroize();
                    }
                    decrypted.zeroize();
                }
                _ => {}
            }
        }
    }

    Ok(secrets)
}

pub fn render_template_file(
    path: &Path,
    age_key_file: Option<&Path>,
) -> Result<Vec<u8>, EnstowError> {
    let template = std::fs::read_to_string(path).map_err(|e| EnstowError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    let host = crate::config::HostInfo::current();
    let secrets = if template.contains("secrets.") {
        load_secret_stores_for_template(path, age_key_file)?
    } else {
        std::collections::BTreeMap::new()
    };

    let ctx = TemplateContext {
        os: host.os,
        arch: host.arch,
        hostname: host.hostname,
        profile: crate::config::get_active_profile().unwrap_or_default(),
        env: std::env::vars().collect(),
        secrets,
    };

    let rendered = render_template(&template, &ctx).map_err(|e| EnstowError::Decryption {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    Ok(rendered.into_bytes())
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
    if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;
    use tempfile::tempdir;

    #[test]
    fn test_clear_session_passphrase() {
        if let Ok(mut lock) = SESSION_PASSPHRASE.lock() {
            *lock = Some(SecretString::from("secret".to_string()));
        }
        clear_session_passphrase();
        if let Ok(lock) = SESSION_PASSPHRASE.lock() {
            assert!(lock.is_none());
        }
    }

    #[test]
    fn test_detect_secret_type() {
        assert_eq!(
            detect_secret_type(Path::new("secret.age")),
            Some(SecretType::Age)
        );
        assert_eq!(
            detect_secret_type(Path::new("secret.sops.yaml")),
            Some(SecretType::Sops)
        );
        assert_eq!(
            detect_secret_type(Path::new(".sops.yaml")),
            Some(SecretType::Sops)
        );
        assert_eq!(
            detect_secret_type(Path::new("config.sops.json")),
            Some(SecretType::Sops)
        );
        assert_eq!(detect_secret_type(Path::new("plain.txt")), None);
        assert_eq!(detect_secret_type(Path::new(".bashrc")), None);
    }

    #[test]
    fn test_target_plaintext_name() {
        assert_eq!(
            target_plaintext_name(Path::new("secret.age")).unwrap(),
            "secret"
        );
        assert_eq!(
            target_plaintext_name(Path::new("secret.sops.yaml")).unwrap(),
            "secret.yaml"
        );
        assert_eq!(
            target_plaintext_name(Path::new("secret.sops.json")).unwrap(),
            "secret.json"
        );
        assert_eq!(
            target_plaintext_name(Path::new("file.sops.txt")).unwrap(),
            "file.txt"
        );
    }

    #[test]
    fn test_get_age_key_paths() {
        let explicit = Path::new("/custom/age/key.txt");
        let paths = get_age_key_paths(Some(explicit));
        assert_eq!(paths[0], PathBuf::from("/custom/age/key.txt"));

        let default_paths = get_age_key_paths(None);
        if std::env::var("HOME").is_ok() || std::env::var("USERPROFILE").is_ok() {
            assert!(!default_paths.is_empty());
        }
    }

    #[test]
    fn test_load_recipients_from_str() {
        assert!(load_recipients_from_str("").unwrap().is_empty());
        assert!(load_recipients_from_str("   ").unwrap().is_empty());
        assert!(load_recipients_from_str("not_a_valid_recipient_string").is_err());
    }

    #[test]
    fn test_write_secure_file() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("secure_file.txt");

        // Initial write succeeds
        assert!(write_secure_file(&target, b"secret data", false).is_ok());
        assert_eq!(std::fs::read(&target).unwrap(), b"secret data");

        // Collision without force fails
        assert!(matches!(
            write_secure_file(&target, b"new data", false),
            Err(EnstowError::Collision { .. })
        ));

        // Overwrite with force succeeds
        assert!(write_secure_file(&target, b"new data", true).is_ok());
        assert_eq!(std::fs::read(&target).unwrap(), b"new data");

        // Write with custom mode
        let target_mode = dir.path().join("mode_file.txt");
        assert!(write_secure_file_with_mode(&target_mode, b"data", false, 0o644).is_ok());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::metadata(&target_mode).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o644);
        }
    }

    #[test]
    fn test_age_roundtrip_with_generated_identity() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("keys.txt");
        let encrypted_path = dir.path().join("secret.txt.age");

        // Generate an x25519 identity
        let identity = age::x25519::Identity::generate();
        let pubkey = identity.to_public();
        let identity_secret = identity.to_string();

        std::fs::write(&key_path, identity_secret.expose_secret()).unwrap();

        let recipient_str = pubkey.to_string();
        let recipient_list =
            resolve_age_recipients(std::slice::from_ref(&recipient_str), Some(&key_path)).unwrap();
        assert_eq!(recipient_list.len(), 1);

        let plaintext = b"Hello, world of enstow tests!";
        encrypt_bytes_age_with_recipients(plaintext, &encrypted_path, &recipient_list).unwrap();

        assert!(encrypted_path.is_file());

        let decrypted = decrypt_age(&encrypted_path, Some(&key_path)).unwrap();
        assert_eq!(decrypted, plaintext);

        // Rekey with new recipient
        let new_identity = age::x25519::Identity::generate();
        let new_pubkey = new_identity.to_public();
        let new_key_path = dir.path().join("new_keys.txt");
        std::fs::write(&new_key_path, new_identity.to_string().expose_secret()).unwrap();

        let new_recipient_list =
            resolve_age_recipients(&[new_pubkey.to_string()], Some(&new_key_path)).unwrap();

        rekey_file_age_with_recipients(&encrypted_path, &new_recipient_list, Some(&key_path))
            .unwrap();

        let re_decrypted = decrypt_age(&encrypted_path, Some(&new_key_path)).unwrap();
        assert_eq!(re_decrypted, plaintext);
    }

    #[test]
    fn test_age_roundtrip_with_passphrase() {
        let dir = tempdir().unwrap();
        let input_path = dir.path().join("plaintext.txt");
        let output_path = dir.path().join("plaintext.txt.age");

        std::fs::write(&input_path, b"passphrase protected dotfile").unwrap();

        let pass = SecretString::from("supersecret123".to_string());
        encrypt_file_age_with_passphrase(&input_path, &output_path, pass).unwrap();
        assert!(output_path.is_file());

        // Decrypt using ENSTOW_PASSPHRASE
        std::env::set_var("ENSTOW_PASSPHRASE", "supersecret123");
        let decrypted = decrypt_age(&output_path, None).unwrap();
        assert_eq!(decrypted, b"passphrase protected dotfile");
        std::env::remove_var("ENSTOW_PASSPHRASE");
        clear_session_passphrase();
    }
}
