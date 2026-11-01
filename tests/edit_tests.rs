use age::secrecy::ExposeSecret;
use age::Recipient;
use clap::Parser;
use enstow::cli::{Cli, Commands};
use enstow::crypto::edit_file_age;
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;

fn setup_age_key_and_file(key_path: &Path, secret_path: &Path, plaintext: &[u8]) {
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(key_path, key.to_string().expose_secret()).unwrap();

    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    fs::write(secret_path, encrypted_buf).unwrap();
}

#[test]
fn test_cli_parsing_edit() {
    let cli = Cli::try_parse_from([
        "enstow",
        "edit",
        "secret.env.age",
        "--age-key-file",
        "/path/to/key.txt",
        "--editor",
        "nano",
    ])
    .unwrap();

    match cli.command {
        Some(Commands::Edit {
            file,
            recipient,
            age_key_file,
            editor,
        }) => {
            assert_eq!(file.to_str().unwrap(), "secret.env.age");
            assert!(recipient.is_empty());
            assert_eq!(age_key_file.unwrap().to_str().unwrap(), "/path/to/key.txt");
            assert_eq!(editor.unwrap(), "nano");
        }
        _ => panic!("Expected Commands::Edit"),
    }
}

#[test]
fn test_edit_file_age_modifies_and_reencrypts() {
    let dir = tempdir().unwrap();
    let key_file = dir.path().join("key.txt");
    let secret_file = dir.path().join("app.env.age");
    setup_age_key_and_file(&key_file, &secret_file, b"INITIAL_SECRET=123\n");

    #[cfg(windows)]
    let editor_cmd = {
        let script = dir.path().join("mock_editor.bat");
        fs::write(
            &script,
            "@echo off\r\n(echo UPDATED_SECRET=456)> \"%~1\"\r\n",
        )
        .unwrap();
        format!("call \"{}\"", script.display())
    };
    #[cfg(not(windows))]
    let editor_cmd = "sh -c 'echo \"UPDATED_SECRET=456\" > \"$1\"' --".to_string();

    let modified = edit_file_age(&secret_file, &[], Some(&key_file), Some(&editor_cmd)).unwrap();
    assert!(modified);

    // Verify decrypted content contains updated secret
    let decrypted = enstow::crypto::decrypt_age(&secret_file, Some(&key_file)).unwrap();
    let content_str = String::from_utf8(decrypted).unwrap();
    assert_eq!(content_str.replace("\r\n", "\n"), "UPDATED_SECRET=456\n");
}

#[test]
fn test_edit_file_age_unchanged_does_not_reencrypt() {
    let dir = tempdir().unwrap();
    let key_file = dir.path().join("key.txt");
    let secret_file = dir.path().join("app.env.age");
    setup_age_key_and_file(&key_file, &secret_file, b"UNCHANGED_SECRET=999\n");

    // Editor command that does not change file content
    let editor_cmd = "true";

    let modified = edit_file_age(&secret_file, &[], Some(&key_file), Some(editor_cmd)).unwrap();
    assert!(!modified);

    let decrypted = enstow::crypto::decrypt_age(&secret_file, Some(&key_file)).unwrap();
    assert_eq!(decrypted, b"UNCHANGED_SECRET=999\n");
}

#[test]
fn test_edit_file_age_editor_failure_errors() {
    let dir = tempdir().unwrap();
    let key_file = dir.path().join("key.txt");
    let secret_file = dir.path().join("app.env.age");
    setup_age_key_and_file(&key_file, &secret_file, b"SECRET_VALUE=1\n");

    // Editor exits with non-zero exit code
    let editor_cmd = "false";

    let result = edit_file_age(&secret_file, &[], Some(&key_file), Some(editor_cmd));
    assert!(result.is_err());

    // File content remains original
    let decrypted = enstow::crypto::decrypt_age(&secret_file, Some(&key_file)).unwrap();
    assert_eq!(decrypted, b"SECRET_VALUE=1\n");
}

#[test]
fn test_edit_file_age_nonexistent_file_errors() {
    let dir = tempdir().unwrap();
    let key_file = dir.path().join("key.txt");
    let missing_file = dir.path().join("nonexistent.env.age");

    let result = edit_file_age(&missing_file, &[], Some(&key_file), Some("true"));
    assert!(result.is_err());
}
