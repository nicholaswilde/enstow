use age::secrecy::ExposeSecret;
use clap::Parser;
use enstow::cli::{Cli, Commands};
use enstow::error::EnstowError;
use enstow::stow::{add_file, is_symlink_to};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_parsing_add_subcommand() {
    let cli =
        Cli::try_parse_from(["enstow", "add", "~/.config/app/config.json", "-p", "app"]).unwrap();

    match cli.command {
        Some(Commands::Add {
            file,
            package,
            encrypt,
            force,
            dry_run,
            ..
        }) => {
            assert_eq!(file, std::path::PathBuf::from("~/.config/app/config.json"));
            assert_eq!(package, "app");
            assert!(!encrypt);
            assert!(!force);
            assert!(!dry_run);
        }
        other => panic!("Expected Commands::Add, got {:?}", other),
    }

    let cli_enc = Cli::try_parse_from([
        "enstow",
        "add",
        "~/.secrets/api.env",
        "--package",
        "secrets",
        "--encrypt",
        "--force",
        "-n",
    ])
    .unwrap();

    match cli_enc.command {
        Some(Commands::Add {
            file,
            package,
            encrypt,
            force,
            dry_run,
            ..
        }) => {
            assert_eq!(file, std::path::PathBuf::from("~/.secrets/api.env"));
            assert_eq!(package, "secrets");
            assert!(encrypt);
            assert!(force);
            assert!(dry_run);
        }
        other => panic!("Expected Commands::Add, got {:?}", other),
    }
}

#[test]
fn test_add_plaintext_file_and_symlink() {
    let src_dir = tempdir().unwrap();
    let tgt_dir = tempdir().unwrap();

    let target_file = tgt_dir
        .path()
        .join(".config")
        .join("app")
        .join("config.json");
    fs::create_dir_all(target_file.parent().unwrap()).unwrap();
    fs::write(&target_file, "{\"enabled\": true}\n").unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target_file, fs::Permissions::from_mode(0o755)).unwrap();
    }

    let (ret_target, ret_source) = add_file(
        &target_file,
        "app",
        false, // encrypt
        &[],
        None,
        src_dir.path(),
        tgt_dir.path(),
        false, // force
        false, // dry_run
    )
    .unwrap();

    let expected_source = src_dir
        .path()
        .join("app")
        .join(".config")
        .join("app")
        .join("config.json");

    assert_eq!(
        fs::canonicalize(&ret_source).unwrap(),
        fs::canonicalize(&expected_source).unwrap()
    );
    assert_eq!(
        fs::canonicalize(&ret_target).unwrap(),
        fs::canonicalize(&target_file).unwrap()
    );

    // Source file must exist with contents
    assert!(expected_source.exists());
    assert_eq!(
        fs::read_to_string(&expected_source).unwrap(),
        "{\"enabled\": true}\n"
    );

    // Target must now be a symlink to expected_source
    assert!(is_symlink_to(&target_file, &expected_source));

    // Permission retention on unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::symlink_metadata(&expected_source)
            .unwrap()
            .permissions();
        assert_eq!(perms.mode() & 0o777, 0o755);
    }
}

#[test]
fn test_add_encrypted_secret_file_and_permissions() {
    let src_dir = tempdir().unwrap();
    let tgt_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let key = age::x25519::Identity::generate();
    let key_file = key_dir.path().join("key.txt");
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    let secret_file = tgt_dir.path().join(".secrets").join("api.env");
    fs::create_dir_all(secret_file.parent().unwrap()).unwrap();
    fs::write(&secret_file, "API_KEY=secret_token_1234\n").unwrap();

    let (ret_target, ret_source) = add_file(
        &secret_file,
        "secrets",
        true, // encrypt
        &[],
        Some(&key_file),
        src_dir.path(),
        tgt_dir.path(),
        false, // force
        false, // dry_run
    )
    .unwrap();

    let expected_source = src_dir
        .path()
        .join("secrets")
        .join(".secrets")
        .join("api.env.age");

    assert_eq!(
        fs::canonicalize(&ret_source).unwrap(),
        fs::canonicalize(&expected_source).unwrap()
    );
    assert_eq!(
        fs::canonicalize(&ret_target).unwrap(),
        fs::canonicalize(&secret_file).unwrap()
    );

    assert!(expected_source.exists());
    // Should be encrypted, not plaintext
    let encrypted_bytes = fs::read(&expected_source).unwrap();
    assert!(!encrypted_bytes.starts_with(b"API_KEY=secret_token_1234"));

    // Decrypting should yield original content
    let decrypted = enstow::crypto::decrypt_age(&expected_source, Some(&key_file)).unwrap();
    assert_eq!(decrypted, b"API_KEY=secret_token_1234\n");

    // Target file must exist with 0600 permissions
    assert!(secret_file.exists());
    assert_eq!(
        fs::read(&secret_file).unwrap(),
        b"API_KEY=secret_token_1234\n"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&secret_file).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}

#[test]
fn test_add_collision_without_force_fails() {
    let src_dir = tempdir().unwrap();
    let tgt_dir = tempdir().unwrap();

    let target_file = tgt_dir.path().join("app.conf");
    fs::write(&target_file, "target_content").unwrap();

    let existing_source = src_dir.path().join("app").join("app.conf");
    fs::create_dir_all(existing_source.parent().unwrap()).unwrap();
    fs::write(&existing_source, "source_content").unwrap();

    // Without force, must error with Collision
    let err = add_file(
        &target_file,
        "app",
        false,
        &[],
        None,
        src_dir.path(),
        tgt_dir.path(),
        false, // force = false
        false,
    );
    assert!(matches!(err, Err(EnstowError::Collision { .. })));

    // With force, must overwrite and succeed
    let res = add_file(
        &target_file,
        "app",
        false,
        &[],
        None,
        src_dir.path(),
        tgt_dir.path(),
        true, // force = true
        false,
    );
    assert!(res.is_ok());
    assert_eq!(
        fs::read_to_string(&existing_source).unwrap(),
        "target_content"
    );
    assert!(is_symlink_to(&target_file, &existing_source));
}

#[test]
fn test_add_dry_run_does_not_modify_disk() {
    let src_dir = tempdir().unwrap();
    let tgt_dir = tempdir().unwrap();

    let target_file = tgt_dir.path().join("test.txt");
    fs::write(&target_file, "hello").unwrap();

    let res = add_file(
        &target_file,
        "base",
        false,
        &[],
        None,
        src_dir.path(),
        tgt_dir.path(),
        false,
        true, // dry_run
    );
    assert!(res.is_ok());

    let source_file = src_dir.path().join("base").join("test.txt");
    assert!(!source_file.exists());
    assert!(!fs::symlink_metadata(&target_file)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_to_string(&target_file).unwrap(), "hello");
}

#[test]
fn test_add_end_to_end_cli() {
    let bin = env!("CARGO_BIN_EXE_enstow");

    match Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => return,
    }

    let src = tempdir().unwrap();
    let tgt = tempdir().unwrap();

    let target_file = tgt.path().join(".config").join("app").join("config.json");
    fs::create_dir_all(target_file.parent().unwrap()).unwrap();
    fs::write(&target_file, "{\"cli\": true}").unwrap();

    let out = Command::new(bin)
        .arg("add")
        .arg(&target_file)
        .arg("-p")
        .arg("app")
        .arg("--source")
        .arg(src.path())
        .arg("--target")
        .arg(tgt.path())
        .output()
        .unwrap();

    assert!(out.status.success(), "add failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Added"));

    let expected_source = src
        .path()
        .join("app")
        .join(".config")
        .join("app")
        .join("config.json");
    assert!(expected_source.exists());
    assert_eq!(
        fs::read_to_string(&expected_source).unwrap(),
        "{\"cli\": true}"
    );
    assert!(is_symlink_to(&target_file, &expected_source));
}
