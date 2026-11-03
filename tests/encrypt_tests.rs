use age::secrecy::ExposeSecret;
use enstow::crypto::{decrypt_age, encrypt_file_age};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_encrypt_file_with_explicit_recipient() {
    let dir = tempdir().unwrap();
    let plaintext_file = dir.path().join("plain.env");
    let encrypted_file = dir.path().join("plain.env.age");
    let content = b"SECRET_API_TOKEN=xyz123\n";
    fs::write(&plaintext_file, content).unwrap();

    // Generate identity and recipient
    let key = age::x25519::Identity::generate();
    let pubkey_str = key.to_public().to_string();

    let key_file = dir.path().join("key.txt");
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    // Encrypt file using public recipient string
    encrypt_file_age(&plaintext_file, &encrypted_file, &[pubkey_str], None).unwrap();

    assert!(encrypted_file.exists());
    // Decrypt and verify payload
    let decrypted = decrypt_age(&encrypted_file, Some(&key_file)).unwrap();
    assert_eq!(decrypted, content);
}

#[test]
fn test_encrypt_file_using_key_file() {
    let dir = tempdir().unwrap();
    let plaintext_file = dir.path().join("credentials.json");
    let encrypted_file = dir.path().join("credentials.json.age");
    let content = b"{\"key\": \"val\"}\n";
    fs::write(&plaintext_file, content).unwrap();

    let key = age::x25519::Identity::generate();
    let key_file = dir.path().join("key.txt");
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    // Encrypt file resolving recipient from identity key file
    encrypt_file_age(&plaintext_file, &encrypted_file, &[], Some(&key_file)).unwrap();

    assert!(encrypted_file.exists());
    let decrypted = decrypt_age(&encrypted_file, Some(&key_file)).unwrap();
    assert_eq!(decrypted, content);
}

fn generate_ssh_key(
    dir: &std::path::Path,
    key_type: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let priv_path = dir.join(format!("id_{key_type}"));
    let mut cmd = std::process::Command::new("ssh-keygen");
    cmd.args(["-t", key_type, "-N", "", "-f"]).arg(&priv_path);
    if key_type == "rsa" {
        cmd.args(["-b", "2048"]);
    }
    let status = cmd.status().expect("Failed to execute ssh-keygen");
    assert!(status.success());
    let pub_path = dir.join(format!("id_{key_type}.pub"));
    (priv_path, pub_path)
}

#[test]
fn test_encrypt_file_with_ssh_ed25519_recipient() {
    let dir = tempdir().unwrap();
    let (priv_key, pub_key) = generate_ssh_key(dir.path(), "ed25519");
    let pubkey_str = fs::read_to_string(&pub_key).unwrap();

    let plaintext_file = dir.path().join("ssh_secret.env");
    let encrypted_file = dir.path().join("ssh_secret.env.age");
    let content = b"SSH_SUPER_SECRET=value123\n";
    fs::write(&plaintext_file, content).unwrap();

    // Encrypt using SSH ed25519 public recipient string
    encrypt_file_age(
        &plaintext_file,
        &encrypted_file,
        &[pubkey_str.trim().to_string()],
        None,
    )
    .unwrap();

    assert!(encrypted_file.exists());
    let decrypted = decrypt_age(&encrypted_file, Some(&priv_key)).unwrap();
    assert_eq!(decrypted, content);
}

#[test]
fn test_encrypt_file_with_ssh_ed25519_pub_file() {
    let dir = tempdir().unwrap();
    let (priv_key, pub_key) = generate_ssh_key(dir.path(), "ed25519");

    let plaintext_file = dir.path().join("file_secret.env");
    let encrypted_file = dir.path().join("file_secret.env.age");
    let content = b"SECRET_FROM_FILE=abc\n";
    fs::write(&plaintext_file, content).unwrap();

    // Encrypt passing the path to the .pub file as recipient
    encrypt_file_age(
        &plaintext_file,
        &encrypted_file,
        &[pub_key.to_string_lossy().to_string()],
        None,
    )
    .unwrap();

    assert!(encrypted_file.exists());
    let decrypted = decrypt_age(&encrypted_file, Some(&priv_key)).unwrap();
    assert_eq!(decrypted, content);
}

#[test]
fn test_encrypt_file_using_ssh_key_file() {
    let dir = tempdir().unwrap();
    let (priv_key, _pub_key) = generate_ssh_key(dir.path(), "ed25519");

    let plaintext_file = dir.path().join("auto_secret.txt");
    let encrypted_file = dir.path().join("auto_secret.txt.age");
    let content = b"auto-extracted ssh recipient\n";
    fs::write(&plaintext_file, content).unwrap();

    // Encrypt resolving recipient from SSH private key file
    encrypt_file_age(&plaintext_file, &encrypted_file, &[], Some(&priv_key)).unwrap();

    assert!(encrypted_file.exists());
    let decrypted = decrypt_age(&encrypted_file, Some(&priv_key)).unwrap();
    assert_eq!(decrypted, content);
}

#[test]
fn test_encrypt_file_with_ssh_rsa_recipient() {
    let dir = tempdir().unwrap();
    let (priv_key, pub_key) = generate_ssh_key(dir.path(), "rsa");
    let pubkey_str = fs::read_to_string(&pub_key).unwrap();

    let plaintext_file = dir.path().join("rsa_secret.txt");
    let encrypted_file = dir.path().join("rsa_secret.txt.age");
    let content = b"RSA_ENCRYPTED_SECRET\n";
    fs::write(&plaintext_file, content).unwrap();

    encrypt_file_age(
        &plaintext_file,
        &encrypted_file,
        &[pubkey_str.trim().to_string()],
        None,
    )
    .unwrap();

    assert!(encrypted_file.exists());
    let decrypted = decrypt_age(&encrypted_file, Some(&priv_key)).unwrap();
    assert_eq!(decrypted, content);
}
