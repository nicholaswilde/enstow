use age::secrecy::ExposeSecret;
use age::Recipient;
use std::fs;
use std::io::Write;
use tempfile::tempdir;

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
    let secret_dest = dir.path().join("subdir/target_secret.txt");
    let content = b"confidential";

    enstow::crypto::write_secure_file(&secret_dest, content).unwrap();

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
    enstow::stow::execute_plan(&actions, false, Some(&key_file)).unwrap();

    assert_eq!(fs::read(&target_dest).unwrap(), plaintext);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(&target_dest).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}
