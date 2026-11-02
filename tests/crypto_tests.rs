use age::secrecy::ExposeSecret;
use age::Recipient;
use enstow::crypto::{
    decrypt_age, decrypt_to_memory, detect_secret_type, edit_file_age, encrypt_file_age,
    target_plaintext_name, write_secure_file, SecretType,
};
use enstow::error::EnstowError;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use tempfile::tempdir;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_detect_secret_type_all_cases() {
    assert_eq!(
        detect_secret_type(Path::new("secret.age")),
        Some(SecretType::Age)
    );
    assert_eq!(
        detect_secret_type(Path::new(".sops.yaml")),
        Some(SecretType::Sops)
    );
    assert_eq!(
        detect_secret_type(Path::new("app.sops.yaml")),
        Some(SecretType::Sops)
    );
    assert_eq!(
        detect_secret_type(Path::new("creds.sops.json")),
        Some(SecretType::Sops)
    );
    assert_eq!(detect_secret_type(Path::new("plain.txt")), None);
}

#[test]
fn test_target_plaintext_name_all_cases() {
    assert_eq!(
        target_plaintext_name(Path::new("secret.age")),
        Some("secret".to_string())
    );
    assert_eq!(
        target_plaintext_name(Path::new(".sops.yaml")),
        Some(".yaml".to_string())
    );
    assert_eq!(
        target_plaintext_name(Path::new("app.sops.yaml")),
        Some("app.yaml".to_string())
    );
    assert_eq!(
        target_plaintext_name(Path::new("config.sops.json")),
        Some("config.json".to_string())
    );
    assert_eq!(
        target_plaintext_name(Path::new("values.sops.env")),
        Some("values.env".to_string())
    );
}

#[test]
fn test_decrypt_age_file() {
    let dir = tempdir().unwrap();
    let key_file = dir.path().join("key.txt");
    let encrypted_file = dir.path().join("secret.txt.age");
    let plaintext = b"super_secret_payload_123\n";

    // Generate age key
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    // Encrypt plaintext with pubkey
    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    fs::write(&encrypted_file, encrypted_buf).unwrap();

    // Call enstow decryption with explicit key file
    let decrypted = enstow::crypto::decrypt_age(&encrypted_file, Some(&key_file)).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[cfg(unix)]
#[test]
fn test_write_secure_file_permissions() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let secret_dest = dir.path().join("subdir").join("target_secret.txt");
    let content = b"confidential";

    enstow::crypto::write_secure_file(&secret_dest, content, false).unwrap();

    let meta = fs::metadata(&secret_dest).unwrap();
    let mode = meta.permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
    assert_eq!(fs::read(&secret_dest).unwrap(), content);
}

#[test]
fn test_execute_plan_decrypts_and_writes_secure_file() {
    let dir = tempdir().unwrap();
    let key_file = dir.path().join("key.txt");
    let source_file = dir.path().join("test.env.age");
    let plaintext = b"DATABASE_URL=postgres://localhost\n";

    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    fs::write(&source_file, encrypted_buf).unwrap();

    let target_dir = tempdir().unwrap();
    let target_dest = target_dir.path().join("test.env");

    let actions = vec![enstow::stow::FileAction::Decrypt {
        source: source_file,
        target: target_dest.clone(),
    }];

    // Run execute_plan with explicit key file
    enstow::stow::execute_plan(&actions, false, Some(&key_file), false).unwrap();

    assert_eq!(fs::read(&target_dest).unwrap(), plaintext);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(&target_dest).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn test_decrypt_age_error_branches() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let dir = tempdir().unwrap();

    let orig_enstow_k = std::env::var("ENSTOW_AGE_KEY_FILE").ok();
    let orig_sops_k = std::env::var("SOPS_AGE_KEY_FILE").ok();
    let orig_home = std::env::var("HOME").ok();

    std::env::remove_var("ENSTOW_AGE_KEY_FILE");
    std::env::remove_var("SOPS_AGE_KEY_FILE");
    std::env::remove_var("HOME");

    let dummy_secret = dir.path().join("dummy.age");
    fs::write(&dummy_secret, b"not_valid_age").unwrap();

    // 1. Key paths completely empty (HOME removed, env vars removed)
    let err = decrypt_age(&dummy_secret, None).unwrap_err();
    assert!(matches!(err, EnstowError::Decryption { .. }));

    // 1b. Test ENSTOW_AGE_KEY_FILE in get_age_key_paths
    std::env::set_var(
        "ENSTOW_AGE_KEY_FILE",
        dir.path().join("nonexistent_key.txt"),
    );
    let err = decrypt_age(&dummy_secret, None).unwrap_err();
    assert!(matches!(err, EnstowError::Decryption { .. }));
    std::env::remove_var("ENSTOW_AGE_KEY_FILE");

    // Restore HOME to empty dir so keys.txt does not exist
    std::env::set_var("HOME", dir.path());

    // 2. Key file exists but contains invalid/empty identities
    let empty_key_file = dir.path().join("empty_key.txt");
    fs::write(&empty_key_file, "# only comments\n").unwrap();
    let err = decrypt_age(&dummy_secret, Some(&empty_key_file)).unwrap_err();
    assert!(matches!(err, EnstowError::Decryption { .. }));

    // 3. Input secret file does not exist
    let valid_key = age::x25519::Identity::generate();
    let valid_key_file = dir.path().join("valid_key.txt");
    fs::write(&valid_key_file, valid_key.to_string().expose_secret()).unwrap();
    let missing_secret = dir.path().join("missing.age");
    let err = decrypt_age(&missing_secret, Some(&valid_key_file)).unwrap_err();
    assert!(matches!(err, EnstowError::Io { .. }));

    // 4. Input secret file contains garbage (age decryptor init fails)
    let err = decrypt_age(&dummy_secret, Some(&valid_key_file)).unwrap_err();
    assert!(matches!(err, EnstowError::Decryption { .. }));

    // 5. Input secret file encrypted with key A, decrypted with key B
    let other_key = age::x25519::Identity::generate();
    let other_pub = other_key.to_public();
    let recip: &dyn Recipient = &other_pub;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recip)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(b"secret").unwrap();
    writer.finish().unwrap();
    let encrypted_with_other = dir.path().join("other.age");
    fs::write(&encrypted_with_other, encrypted_buf).unwrap();

    let err = decrypt_age(&encrypted_with_other, Some(&valid_key_file)).unwrap_err();
    assert!(matches!(err, EnstowError::Decryption { .. }));

    // 6. Test decrypt_to_memory dispatch
    let decrypted = decrypt_to_memory(
        &encrypted_with_other,
        SecretType::Age,
        Some(&dir.path().join("other_key.txt")),
    );
    assert!(decrypted.is_err());

    let sops_file = dir.path().join("some.sops.yaml");
    fs::write(&sops_file, "foo: bar").unwrap();
    let sops_res = decrypt_to_memory(&sops_file, SecretType::Sops, None);
    assert!(sops_res.is_err()); // sops cli fails or not configured for this file

    if let Some(v) = orig_enstow_k {
        std::env::set_var("ENSTOW_AGE_KEY_FILE", v);
    }
    if let Some(v) = orig_sops_k {
        std::env::set_var("SOPS_AGE_KEY_FILE", v);
    }
    if let Some(v) = orig_home {
        std::env::set_var("HOME", v);
    }
}

#[test]
fn test_encrypt_file_age_env_and_error_paths() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let dir = tempdir().unwrap();

    let key = age::x25519::Identity::generate();
    let pubkey_str = key.to_public().to_string();

    let input_file = dir.path().join("input.txt");
    fs::write(&input_file, b"content").unwrap();
    let output_file = dir.path().join("output.age");

    // 1. Missing input file
    let missing_input = dir.path().join("nonexistent.txt");
    let err = encrypt_file_age(
        &missing_input,
        &output_file,
        std::slice::from_ref(&pubkey_str),
        None,
    )
    .unwrap_err();
    assert!(matches!(err, EnstowError::Io { .. }));

    // 2. No recipients provided and no env vars set (set HOME to empty dir and clear key env vars)
    let orig_recs = std::env::var("ENSTOW_RECIPIENTS").ok();
    let orig_sops_recs = std::env::var("SOPS_AGE_RECIPIENTS").ok();
    let orig_home = std::env::var("HOME").ok();
    let orig_enstow_k = std::env::var("ENSTOW_AGE_KEY_FILE").ok();
    let orig_sops_k = std::env::var("SOPS_AGE_KEY_FILE").ok();

    std::env::remove_var("ENSTOW_RECIPIENTS");
    std::env::remove_var("SOPS_AGE_RECIPIENTS");
    std::env::remove_var("ENSTOW_AGE_KEY_FILE");
    std::env::remove_var("SOPS_AGE_KEY_FILE");
    std::env::set_var("HOME", dir.path());

    let err = encrypt_file_age(&input_file, &output_file, &[], None).unwrap_err();
    assert!(matches!(err, EnstowError::Config(_)));

    // 3. Encrypt via ENSTOW_RECIPIENTS env var
    std::env::set_var("ENSTOW_RECIPIENTS", format!("{},", pubkey_str));
    encrypt_file_age(&input_file, &output_file, &[], None).unwrap();
    assert!(output_file.exists());
    fs::remove_file(&output_file).unwrap();

    // 4. Encrypt via SOPS_AGE_RECIPIENTS env var
    std::env::remove_var("ENSTOW_RECIPIENTS");
    std::env::set_var("SOPS_AGE_RECIPIENTS", format!("\n{}\n", pubkey_str));
    encrypt_file_age(&input_file, &output_file, &[], None).unwrap();
    assert!(output_file.exists());

    std::env::remove_var("SOPS_AGE_RECIPIENTS");
    if let Some(v) = orig_recs {
        std::env::set_var("ENSTOW_RECIPIENTS", v);
    }
    if let Some(v) = orig_sops_recs {
        std::env::set_var("SOPS_AGE_RECIPIENTS", v);
    }
    if let Some(v) = orig_home {
        std::env::set_var("HOME", v);
    }
    if let Some(v) = orig_enstow_k {
        std::env::set_var("ENSTOW_AGE_KEY_FILE", v);
    }
    if let Some(v) = orig_sops_k {
        std::env::set_var("SOPS_AGE_KEY_FILE", v);
    }
}

#[test]
fn test_write_secure_file_collision_and_force() {
    let dir = tempdir().unwrap();
    let target_file = dir.path().join("target.txt");
    fs::write(&target_file, b"old_content").unwrap();

    // 1. Collision when force=false
    let err = write_secure_file(&target_file, b"new_content", false).unwrap_err();
    assert!(matches!(err, EnstowError::Collision { .. }));

    // 2. Overwrite file when force=true
    write_secure_file(&target_file, b"new_content", true).unwrap();
    assert_eq!(fs::read(&target_file).unwrap(), b"new_content");

    // 3. Overwrite directory when force=true
    let target_dir = dir.path().join("target_dir");
    fs::create_dir_all(&target_dir).unwrap();
    fs::write(target_dir.join("subfile"), b"dummy").unwrap();

    write_secure_file(&target_dir, b"from_dir_to_file", true).unwrap();
    assert!(target_dir.is_file());
    assert_eq!(fs::read(&target_dir).unwrap(), b"from_dir_to_file");
}

#[test]
fn test_edit_file_age_not_age_file() {
    let dir = tempdir().unwrap();
    let plain = dir.path().join("file.txt");
    fs::write(&plain, b"text").unwrap();
    let err = edit_file_age(&plain, &[], None, Some("true")).unwrap_err();
    assert!(matches!(err, EnstowError::Config(_)));
}

#[cfg(unix)]
#[test]
fn test_decrypt_sops_all_branches() {
    use std::os::unix::fs::PermissionsExt;
    let _lock = ENV_MUTEX.lock().unwrap();
    let dir = tempdir().unwrap();

    let orig_path = std::env::var("PATH").unwrap_or_default();
    let mock_file = dir.path().join("test.sops.yaml");
    fs::write(&mock_file, "foo: bar").unwrap();

    // 1. PATH contains no sops executable -> fails to execute sops
    std::env::set_var("PATH", dir.path()); // empty dir
    let err = enstow::crypto::decrypt_sops(&mock_file).unwrap_err();
    assert!(matches!(err, EnstowError::Decryption { .. }));
    let err_msg = err.to_string();
    assert!(err_msg.contains("Failed to execute `sops`"));

    // 2. PATH has mock sops that fails (status != 0)
    let mock_bin_dir = dir.path().join("bin");
    fs::create_dir_all(&mock_bin_dir).unwrap();
    let mock_sops = mock_bin_dir.join("sops");
    fs::write(
        &mock_sops,
        "#!/bin/sh\necho 'simulated error' >&2\nexit 1\n",
    )
    .unwrap();
    fs::set_permissions(&mock_sops, fs::Permissions::from_mode(0o755)).unwrap();

    std::env::set_var("PATH", format!("{}:{}", mock_bin_dir.display(), orig_path));
    let err = enstow::crypto::decrypt_sops(&mock_file).unwrap_err();
    assert!(matches!(err, EnstowError::Decryption { .. }));
    let err_msg = err.to_string();
    assert!(err_msg.contains("sops decryption failed: simulated error"));

    // 3. PATH has mock sops that succeeds
    fs::write(&mock_sops, "#!/bin/sh\necho 'decrypted payload'\nexit 0\n").unwrap();
    let out = enstow::crypto::decrypt_sops(&mock_file).unwrap();
    assert_eq!(String::from_utf8_lossy(&out).trim(), "decrypted payload");

    std::env::set_var("PATH", orig_path);
}
