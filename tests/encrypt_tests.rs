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
