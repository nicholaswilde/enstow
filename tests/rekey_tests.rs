use age::secrecy::ExposeSecret;
use age::Recipient;
use clap::Parser;
use enstow::cli::{Cli, Commands};
use enstow::crypto::decrypt_age;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
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
    if let Some(parent) = secret_path.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(secret_path, encrypted_buf).unwrap();
}

#[test]
fn test_cli_parsing_rekey() {
    let cli = Cli::try_parse_from([
        "enstow",
        "rekey",
        "-r",
        "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p",
        "-r",
        "age1y7n0q2k8q6l8m46z8u9y7z2v4c6x8w0e2r4t6y8u0i2o4p6a8s0d2f4g6h",
        "--age-key-file",
        "/tmp/key.txt",
        "-n",
        "-s",
        "/tmp/dotfiles",
        "pkg1",
        "pkg2",
    ])
    .unwrap();

    match cli.command {
        Some(Commands::Rekey {
            recipient,
            age_key_file,
            dry_run,
            source,
            profile,
            ignore,
            packages,
        }) => {
            assert_eq!(recipient.len(), 2);
            assert_eq!(
                recipient[0],
                "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
            );
            assert_eq!(age_key_file, Some(PathBuf::from("/tmp/key.txt")));
            assert!(dry_run);
            assert_eq!(source, Some(PathBuf::from("/tmp/dotfiles")));
            assert_eq!(profile, None);
            assert!(ignore.is_empty());
            assert_eq!(packages, vec!["pkg1", "pkg2"]);
        }
        other => panic!("Expected Commands::Rekey, got {:?}", other),
    }
}

#[test]
fn test_rekey_single_recipient_updates_age_files() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("dotfiles");
    let key1_file = dir.path().join("key1.txt");
    let key2_file = dir.path().join("key2.txt");

    // Setup key1 and files
    let secret1 = src.join("pkg1").join("secret1.env.age");
    let secret2 = src.join("pkg2").join("nested").join("secret2.json.age");
    let regular_file = src.join("pkg1").join("config.toml");

    let content1 = b"API_KEY=key1_secret\n";
    let content2 = b"{\"token\": \"abc123xyz\"}\n";
    let regular_content = b"setting = true\n";

    setup_age_key_and_file(&key1_file, &secret1, content1);

    // Also encrypt secret2 with key1
    let key1_str = fs::read_to_string(&key1_file).unwrap();
    let id1: age::x25519::Identity = key1_str.trim().parse().unwrap();
    let recip1 = id1.to_public();
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(&recip1 as &dyn Recipient)).unwrap();
    let mut buf = vec![];
    let mut writer = encryptor.wrap_output(&mut buf).unwrap();
    writer.write_all(content2).unwrap();
    writer.finish().unwrap();
    fs::create_dir_all(secret2.parent().unwrap()).unwrap();
    fs::write(&secret2, buf).unwrap();

    fs::write(&regular_file, regular_content).unwrap();

    // Setup key2
    let key2 = age::x25519::Identity::generate();
    let pubkey2_str = key2.to_public().to_string();
    fs::write(&key2_file, key2.to_string().expose_secret()).unwrap();

    // Rekey using enstow::crypto::rekey or rekey execution
    enstow::crypto::rekey_packages(&src, &[], &[], &[pubkey2_str], Some(&key1_file), false)
        .unwrap();

    // Verify key2 can decrypt both secrets
    let dec1 = decrypt_age(&secret1, Some(&key2_file)).unwrap();
    assert_eq!(dec1, content1);

    let dec2 = decrypt_age(&secret2, Some(&key2_file)).unwrap();
    assert_eq!(dec2, content2);

    // Verify key1 can NO LONGER decrypt secrets
    assert!(decrypt_age(&secret1, Some(&key1_file)).is_err());
    assert!(decrypt_age(&secret2, Some(&key1_file)).is_err());

    // Verify regular file is unchanged
    assert_eq!(fs::read(&regular_file).unwrap(), regular_content);
}

#[test]
fn test_rekey_multi_recipient() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("dotfiles");
    let key1_file = dir.path().join("key1.txt");
    let key2_file = dir.path().join("key2.txt");
    let key3_file = dir.path().join("key3.txt");

    let secret = src.join("pkg").join("secret.age");
    let content = b"MULTI_RECIPIENT_SECRET=true\n";

    setup_age_key_and_file(&key1_file, &secret, content);

    let key2 = age::x25519::Identity::generate();
    let pubkey2 = key2.to_public().to_string();
    fs::write(&key2_file, key2.to_string().expose_secret()).unwrap();

    let key3 = age::x25519::Identity::generate();
    let pubkey3 = key3.to_public().to_string();
    fs::write(&key3_file, key3.to_string().expose_secret()).unwrap();

    // Rekey with multiple recipients: [pubkey2, pubkey3]
    enstow::crypto::rekey_packages(
        &src,
        &["pkg".to_string()],
        &[],
        &[pubkey2, pubkey3],
        Some(&key1_file),
        false,
    )
    .unwrap();

    // Both key2 and key3 should decrypt
    let dec2 = decrypt_age(&secret, Some(&key2_file)).unwrap();
    assert_eq!(dec2, content);

    let dec3 = decrypt_age(&secret, Some(&key3_file)).unwrap();
    assert_eq!(dec3, content);

    // key1 cannot decrypt
    assert!(decrypt_age(&secret, Some(&key1_file)).is_err());
}

#[test]
fn test_rekey_dry_run_does_not_modify_files() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("dotfiles");
    let key1_file = dir.path().join("key1.txt");
    let key2_file = dir.path().join("key2.txt");

    let secret = src.join("pkg").join("secret.age");
    let content = b"DRY_RUN_SECRET\n";

    setup_age_key_and_file(&key1_file, &secret, content);
    let original_bytes = fs::read(&secret).unwrap();

    let key2 = age::x25519::Identity::generate();
    let pubkey2 = key2.to_public().to_string();
    fs::write(&key2_file, key2.to_string().expose_secret()).unwrap();

    enstow::crypto::rekey_packages(
        &src,
        &["pkg".to_string()],
        &[],
        &[pubkey2],
        Some(&key1_file),
        true, // dry_run
    )
    .unwrap();

    // Bytes must be identical
    assert_eq!(fs::read(&secret).unwrap(), original_bytes);

    // key1 can still decrypt
    assert_eq!(decrypt_age(&secret, Some(&key1_file)).unwrap(), content);

    // key2 cannot decrypt
    assert!(decrypt_age(&secret, Some(&key2_file)).is_err());
}

#[test]
fn test_rekey_invalid_recipient_errors_without_modifying_files() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("dotfiles");
    let key1_file = dir.path().join("key1.txt");

    let secret = src.join("pkg").join("secret.age");
    let content = b"SAFE_DATA\n";

    setup_age_key_and_file(&key1_file, &secret, content);
    let original_bytes = fs::read(&secret).unwrap();

    let err = enstow::crypto::rekey_packages(
        &src,
        &[],
        &[],
        &["invalid-recipient-pubkey".to_string()],
        Some(&key1_file),
        false,
    )
    .unwrap_err();

    assert!(matches!(err, enstow::error::EnstowError::Config(_)));
    assert_eq!(fs::read(&secret).unwrap(), original_bytes);
}

#[test]
fn test_rekey_invalid_age_key_errors_without_modifying_files() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("dotfiles");
    let key1_file = dir.path().join("key1.txt");
    let key2_file = dir.path().join("key2.txt");
    let wrong_key_file = dir.path().join("wrong.txt");

    let secret = src.join("pkg").join("secret.age");
    let content = b"SECURE\n";

    setup_age_key_and_file(&key1_file, &secret, content);
    let original_bytes = fs::read(&secret).unwrap();

    let key2 = age::x25519::Identity::generate();
    let pubkey2 = key2.to_public().to_string();
    fs::write(&key2_file, key2.to_string().expose_secret()).unwrap();

    let wrong_key = age::x25519::Identity::generate();
    fs::write(&wrong_key_file, wrong_key.to_string().expose_secret()).unwrap();

    let err =
        enstow::crypto::rekey_packages(&src, &[], &[], &[pubkey2], Some(&wrong_key_file), false)
            .unwrap_err();

    assert!(matches!(err, enstow::error::EnstowError::Decryption { .. }));
    assert_eq!(fs::read(&secret).unwrap(), original_bytes);
}

#[test]
fn test_rekey_binary_cli_e2e() {
    let bin = env!("CARGO_BIN_EXE_enstow");

    match Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => {
            eprintln!("Skipping end-to-end binary test: target binary cannot be executed");
            return;
        }
    }

    let dir = tempdir().unwrap();
    let src = dir.path().join("dotfiles");
    let key1_file = dir.path().join("key1.txt");
    let key2_file = dir.path().join("key2.txt");

    let secret = src.join("pkg").join("secret.age");
    let content = b"CLI_E2E_SECRET\n";
    setup_age_key_and_file(&key1_file, &secret, content);

    let key2 = age::x25519::Identity::generate();
    let pubkey2 = key2.to_public().to_string();
    fs::write(&key2_file, key2.to_string().expose_secret()).unwrap();

    // 1. Dry run via CLI
    let dry_run_out = Command::new(bin)
        .arg("rekey")
        .arg("-s")
        .arg(&src)
        .arg("-r")
        .arg(&pubkey2)
        .arg("--age-key-file")
        .arg(&key1_file)
        .arg("-n")
        .arg("pkg")
        .output()
        .unwrap();

    assert!(dry_run_out.status.success());
    let stdout = String::from_utf8_lossy(&dry_run_out.stdout);
    assert!(stdout.contains("[dry-run] REKEY"));
    assert!(stdout.contains("secret.age"));

    // File should still decrypt with key1, not key2
    assert_eq!(decrypt_age(&secret, Some(&key1_file)).unwrap(), content);
    assert!(decrypt_age(&secret, Some(&key2_file)).is_err());

    // 2. Actual execution via CLI
    let rekey_out = Command::new(bin)
        .arg("rekey")
        .arg("-s")
        .arg(&src)
        .arg("-r")
        .arg(&pubkey2)
        .arg("--age-key-file")
        .arg(&key1_file)
        .arg("pkg")
        .output()
        .unwrap();

    assert!(rekey_out.status.success());
    let stdout = String::from_utf8_lossy(&rekey_out.stdout);
    assert!(
        stdout.contains("Rekeyed") || stdout.contains("re-encrypted") || stdout.contains("REKEY")
    );

    // Now key2 decrypts, key1 fails
    assert_eq!(decrypt_age(&secret, Some(&key2_file)).unwrap(), content);
    assert!(decrypt_age(&secret, Some(&key1_file)).is_err());
}
