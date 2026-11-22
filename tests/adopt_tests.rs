use age::secrecy::ExposeSecret;
use clap::Parser;
use enstow::cli::{Cli, Commands, CommonArgs};
use enstow::stow::{execute_plan_with_backup_and_permissions, is_symlink_to, plan_stow};
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_parsing_adopt_flag() {
    let cli = Cli::try_parse_from(["enstow", "apply", "--adopt"]).unwrap();
    match cli.command {
        Some(Commands::Apply(common)) => {
            assert!(common.adopt);
        }
        other => panic!("Expected Commands::Apply, got {:?}", other),
    }

    let cli_no_adopt = Cli::try_parse_from(["enstow", "apply"]).unwrap();
    match cli_no_adopt.command {
        Some(Commands::Apply(common)) => {
            assert!(!common.adopt);
        }
        other => panic!("Expected Commands::Apply, got {:?}", other),
    }
}

#[test]
fn test_apply_adopt_conflicting_file() {
    let src_dir = tempdir().unwrap();
    let tgt_dir = tempdir().unwrap();

    let source_file = src_dir.path().join("app").join(".bashrc");
    fs::create_dir_all(source_file.parent().unwrap()).unwrap();
    fs::write(&source_file, "source content\n").unwrap();

    let target_file = tgt_dir.path().join(".bashrc");
    fs::write(&target_file, "machine adopted content\n").unwrap();

    let common = CommonArgs {
        source: Some(src_dir.path().to_path_buf()),
        target: Some(tgt_dir.path().to_path_buf()),
        packages: vec!["app".to_string()],
        adopt: true,
        ..Default::default()
    };

    let actions = plan_stow(&common).unwrap();
    assert_eq!(actions.len(), 1);

    execute_plan_with_backup_and_permissions(
        &actions,
        false, // dry_run
        None,
        false, // force
        false, // backup
        None,
        Some(tgt_dir.path()),
        None,
        true, // adopt = true
    )
    .unwrap();

    // Source file should have been overwritten with target file's content
    assert_eq!(
        fs::read_to_string(&source_file).unwrap(),
        "machine adopted content\n"
    );

    // Target file should now be a symlink to source_file
    assert!(is_symlink_to(&target_file, &source_file));
}

#[test]
fn test_apply_adopt_dry_run() {
    let src_dir = tempdir().unwrap();
    let tgt_dir = tempdir().unwrap();

    let source_file = src_dir.path().join("app").join(".bashrc");
    fs::create_dir_all(source_file.parent().unwrap()).unwrap();
    fs::write(&source_file, "source content\n").unwrap();

    let target_file = tgt_dir.path().join(".bashrc");
    fs::write(&target_file, "machine adopted content\n").unwrap();

    let common = CommonArgs {
        source: Some(src_dir.path().to_path_buf()),
        target: Some(tgt_dir.path().to_path_buf()),
        packages: vec!["app".to_string()],
        adopt: true,
        dry_run: true,
        ..Default::default()
    };

    let actions = plan_stow(&common).unwrap();
    assert_eq!(actions.len(), 1);

    execute_plan_with_backup_and_permissions(
        &actions,
        true, // dry_run
        None,
        false, // force
        false, // backup
        None,
        Some(tgt_dir.path()),
        None,
        true, // adopt = true
    )
    .unwrap();

    // Source and target must be unmodified
    assert_eq!(
        fs::read_to_string(&source_file).unwrap(),
        "source content\n"
    );
    assert_eq!(
        fs::read_to_string(&target_file).unwrap(),
        "machine adopted content\n"
    );
    assert!(!fs::symlink_metadata(&target_file)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn test_apply_adopt_encrypted_secret() {
    let src_dir = tempdir().unwrap();
    let tgt_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    let key_file = key_dir.path().join("key.txt");
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    // Initial secret in source package
    let source_secret = src_dir.path().join("secrets").join("secret.env.age");
    fs::create_dir_all(source_secret.parent().unwrap()).unwrap();
    let recipient: &dyn age::Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    std::io::Write::write_all(&mut writer, b"INITIAL_SECRET=old\n").unwrap();
    writer.finish().unwrap();
    fs::write(&source_secret, encrypted_buf).unwrap();

    // Conflicting target file with modified local secret
    let target_secret = tgt_dir.path().join("secret.env");
    fs::write(&target_secret, "INITIAL_SECRET=new_locally_edited\n").unwrap();

    let common = CommonArgs {
        source: Some(src_dir.path().to_path_buf()),
        target: Some(tgt_dir.path().to_path_buf()),
        packages: vec!["secrets".to_string()],
        age_key_file: Some(key_file.clone()),
        adopt: true,
        ..Default::default()
    };

    let actions = plan_stow(&common).unwrap();
    assert_eq!(actions.len(), 1);

    execute_plan_with_backup_and_permissions(
        &actions,
        false, // dry_run
        Some(&key_file),
        false, // force
        false, // backup
        None,
        Some(tgt_dir.path()),
        None,
        true, // adopt = true
    )
    .unwrap();

    // Source secret must have been re-encrypted with new content
    let decrypted = enstow::crypto::decrypt_age(&source_secret, Some(&key_file)).unwrap();
    assert_eq!(decrypted, b"INITIAL_SECRET=new_locally_edited\n");

    // Target file must have 0600 permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::metadata(&target_secret).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }
}

#[test]
fn test_adopt_end_to_end_cli() {
    let bin = env!("CARGO_BIN_EXE_enstow");

    match Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => return,
    }

    let src = tempdir().unwrap();
    let tgt = tempdir().unwrap();

    let source_file = src.path().join("pkg").join("dot.profile");
    fs::create_dir_all(source_file.parent().unwrap()).unwrap();
    fs::write(&source_file, "old profile\n").unwrap();

    let target_file = tgt.path().join("dot.profile");
    fs::write(&target_file, "adopted profile\n").unwrap();

    let out = Command::new(bin)
        .arg("apply")
        .arg("--adopt")
        .arg("--source")
        .arg(src.path())
        .arg("--target")
        .arg(tgt.path())
        .arg("pkg")
        .output()
        .unwrap();

    assert!(out.status.success(), "apply --adopt failed: {:?}", out);
    assert_eq!(
        fs::read_to_string(&source_file).unwrap(),
        "adopted profile\n"
    );
    assert!(is_symlink_to(&target_file, &source_file));
}

#[test]
fn test_adopt_encrypted_secret_honors_config_recipients_cli() {
    use age::secrecy::ExposeSecret;

    let bin = env!("CARGO_BIN_EXE_enstow");

    match Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => return,
    }

    let workspace = tempdir().unwrap();
    let src_dir = workspace.path().join("dotfiles");
    let tgt_dir = workspace.path().join("target");
    let key_dir = workspace.path().join("keys");
    fs::create_dir_all(src_dir.join("secrets")).unwrap();
    fs::create_dir_all(&tgt_dir).unwrap();
    fs::create_dir_all(&key_dir).unwrap();

    let primary_key = age::x25519::Identity::generate();
    let backup_key = age::x25519::Identity::generate();
    let primary_pub = primary_key.to_public();
    let backup_pub = backup_key.to_public();

    let primary_key_file = key_dir.join("primary.txt");
    let backup_key_file = key_dir.join("backup.txt");
    fs::write(&primary_key_file, primary_key.to_string().expose_secret()).unwrap();
    fs::write(&backup_key_file, backup_key.to_string().expose_secret()).unwrap();

    let source_secret = src_dir.join("secrets").join("secret.env.age");
    let recips: Vec<&dyn age::Recipient> = vec![&primary_pub, &backup_pub];
    let encryptor = age::Encryptor::with_recipients(recips.into_iter()).unwrap();
    let mut encrypted_buf = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    std::io::Write::write_all(&mut writer, b"TOKEN=initial\n").unwrap();
    writer.finish().unwrap();
    fs::write(&source_secret, encrypted_buf).unwrap();

    fs::write(
        src_dir.join(".enstow.toml"),
        format!(
            "source = \".\"\npackages = [\"secrets\"]\nrecipients = [\"{primary_pub}\", \"{backup_pub}\"]\n"
        ),
    )
    .unwrap();

    // Locally edited secret in target
    let target_secret = tgt_dir.join("secret.env");
    fs::write(&target_secret, "TOKEN=adopted_local\n").unwrap();

    let out = Command::new(bin)
        .current_dir(&src_dir)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_RECIPIENTS")
        .env_remove("SOPS_AGE_RECIPIENTS")
        .args([
            "apply",
            "--adopt",
            "--target",
            tgt_dir.to_str().unwrap(),
            "--age-key-file",
            primary_key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "apply --adopt failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Both configured recipients (primary AND backup) must be able to decrypt
    assert_eq!(
        enstow::crypto::decrypt_age(&source_secret, Some(&primary_key_file)).unwrap(),
        b"TOKEN=adopted_local\n"
    );
    assert_eq!(
        enstow::crypto::decrypt_age(&source_secret, Some(&backup_key_file)).unwrap(),
        b"TOKEN=adopted_local\n"
    );
}

#[test]
fn test_adopt_encrypted_secret_honors_config_recipients_in_process() {
    use age::secrecy::ExposeSecret;
    use enstow::config::{resolve_common_args, ConfigFile};
    use enstow::stow::execute_plan_interactive;

    let workspace = tempdir().unwrap();
    let src_dir = workspace.path().join("dotfiles");
    let tgt_dir = workspace.path().join("target");
    let key_dir = workspace.path().join("keys");
    fs::create_dir_all(src_dir.join("secrets")).unwrap();
    fs::create_dir_all(&tgt_dir).unwrap();
    fs::create_dir_all(&key_dir).unwrap();

    let primary_key = age::x25519::Identity::generate();
    let backup_key = age::x25519::Identity::generate();
    let primary_pub = primary_key.to_public();
    let backup_pub = backup_key.to_public();

    let primary_key_file = key_dir.join("primary.txt");
    let backup_key_file = key_dir.join("backup.txt");
    fs::write(&primary_key_file, primary_key.to_string().expose_secret()).unwrap();
    fs::write(&backup_key_file, backup_key.to_string().expose_secret()).unwrap();

    let source_secret = src_dir.join("secrets").join("secret.env.age");
    let recips: Vec<&dyn age::Recipient> = vec![&primary_pub, &backup_pub];
    let encryptor = age::Encryptor::with_recipients(recips.into_iter()).unwrap();
    let mut encrypted_buf = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    std::io::Write::write_all(&mut writer, b"TOKEN=initial\n").unwrap();
    writer.finish().unwrap();
    fs::write(&source_secret, encrypted_buf).unwrap();

    let cfg_path = src_dir.join(".enstow.toml");
    fs::write(
        &cfg_path,
        format!(
            "source = \".\"\npackages = [\"secrets\"]\nrecipients = [\"{primary_pub}\", \"{backup_pub}\"]\n"
        ),
    )
    .unwrap();
    let config = ConfigFile::load_from_path(&cfg_path).unwrap();

    let target_secret = tgt_dir.join("secret.env");
    fs::write(&target_secret, "TOKEN=adopted_in_process\n").unwrap();

    let cli_args = CommonArgs {
        target: Some(tgt_dir.clone()),
        age_key_file: Some(primary_key_file.clone()),
        adopt: true,
        ..Default::default()
    };
    let resolved = resolve_common_args(&cli_args, Some(&config)).unwrap();
    assert_eq!(
        resolved.recipients,
        vec![primary_pub.to_string(), backup_pub.to_string()]
    );

    let common = resolved.to_common_args();
    let actions = plan_stow(&common).unwrap();
    execute_plan_interactive(
        &actions,
        false,
        common.age_key_file.as_deref(),
        &resolved.recipients,
        false,
        false,
        None,
        Some(&tgt_dir),
        Some(&resolved.permissions),
        true,
        false,
    )
    .unwrap();

    assert_eq!(
        enstow::crypto::decrypt_age(&source_secret, Some(&primary_key_file)).unwrap(),
        b"TOKEN=adopted_in_process\n"
    );
    assert_eq!(
        enstow::crypto::decrypt_age(&source_secret, Some(&backup_key_file)).unwrap(),
        b"TOKEN=adopted_in_process\n"
    );
}
