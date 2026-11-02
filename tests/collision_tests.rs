use enstow::cli::CommonArgs;
use enstow::error::EnstowError;
use enstow::stow::{execute_plan, plan_stow, FileAction};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_skip_existing_identical_symlink() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let file = source_dir.path().join("dot.bashrc");
    fs::write(&file, "alias ll='ls -la'").unwrap();

    let target_link = target_dir.path().join("dot.bashrc");

    // Pre-create identical symlink
    #[cfg(unix)]
    std::os::unix::fs::symlink(&file, &target_link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&file, &target_link).unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: false,
        age_key_file: None,
        force: false,
        prune: false,
        packages: Vec::new(),
        ignore: Vec::new(),
        ..Default::default()
    };

    let actions = plan_stow(&args).unwrap();
    // Should execute cleanly without error
    execute_plan(&actions, false, None, false).unwrap();
}

#[test]
fn test_collision_with_existing_file_fails_without_force() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let file = source_dir.path().join("app.conf");
    fs::write(&file, "new config").unwrap();

    let existing_target = target_dir.path().join("app.conf");
    fs::write(&existing_target, "existing unmanaged file").unwrap();

    let actions = vec![FileAction::Symlink {
        source: file.clone(),
        target: existing_target.clone(),
    }];

    // Without force, should return Collision error
    let res = execute_plan(&actions, false, None, false);
    match res {
        Err(EnstowError::Collision { path }) => {
            assert_eq!(path, existing_target);
        }
        other => panic!("Expected Collision error, got {:?}", other),
    }

    // Verify existing file is preserved
    assert_eq!(
        fs::read_to_string(&existing_target).unwrap(),
        "existing unmanaged file"
    );
}

#[test]
fn test_collision_overwritten_with_force() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let file = source_dir.path().join("app.conf");
    fs::write(&file, "new config").unwrap();

    let existing_target = target_dir.path().join("app.conf");
    fs::write(&existing_target, "existing unmanaged file").unwrap();

    let actions = vec![FileAction::Symlink {
        source: file.clone(),
        target: existing_target.clone(),
    }];

    // With force=true, should succeed and overwrite/replace target
    execute_plan(&actions, false, None, true).unwrap();

    assert!(fs::symlink_metadata(&existing_target)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(enstow::stow::is_symlink_to(&existing_target, &file));
}

#[test]
fn test_collision_backed_up_to_default_backup_dir() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let file = source_dir.path().join("app.conf");
    fs::write(&file, "new config").unwrap();

    let existing_target = target_dir.path().join("app.conf");
    fs::write(&existing_target, "existing unmanaged file").unwrap();

    let default_backup_dir = target_dir.path().join(".enstow-backup");
    let backup_file = default_backup_dir.join("app.conf");

    let actions = vec![FileAction::Symlink {
        source: file.clone(),
        target: existing_target.clone(),
    }];

    // Execute with backup=true and default backup dir
    enstow::stow::execute_plan_with_backup(
        &actions,
        false,
        None,
        false,
        true,
        Some(&default_backup_dir),
        Some(target_dir.path()),
    )
    .unwrap();

    // 1. Target is now a symlink pointing to source
    assert!(fs::symlink_metadata(&existing_target)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(enstow::stow::is_symlink_to(&existing_target, &file));

    // 2. Original collision file was safely relocated to backup directory
    assert!(backup_file.exists());
    assert_eq!(
        fs::read_to_string(&backup_file).unwrap(),
        "existing unmanaged file"
    );

    // 3. Verify collision file is restorable
    fs::remove_file(&existing_target).unwrap();
    fs::rename(&backup_file, &existing_target).unwrap();
    assert_eq!(
        fs::read_to_string(&existing_target).unwrap(),
        "existing unmanaged file"
    );
}

#[test]
fn test_collision_backed_up_to_custom_backup_dir() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let custom_backup_dir = tempdir().unwrap();

    let file = source_dir.path().join("app.conf");
    fs::write(&file, "new config").unwrap();

    let existing_target = target_dir.path().join("app.conf");
    fs::write(&existing_target, "existing content in target").unwrap();

    let actions = vec![FileAction::Symlink {
        source: file.clone(),
        target: existing_target.clone(),
    }];

    enstow::stow::execute_plan_with_backup(
        &actions,
        false,
        None,
        false,
        true,
        Some(custom_backup_dir.path()),
        Some(target_dir.path()),
    )
    .unwrap();

    // Relocated to custom backup dir
    let backup_file = custom_backup_dir.path().join("app.conf");
    assert!(backup_file.exists());
    assert_eq!(
        fs::read_to_string(&backup_file).unwrap(),
        "existing content in target"
    );

    // Default backup dir should not have been created
    assert!(!target_dir.path().join(".enstow-backup").exists());
}

#[test]
fn test_collision_nested_directory_backed_up() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let sub_src = source_dir.path().join("config").join("sub");
    fs::create_dir_all(&sub_src).unwrap();
    let file = sub_src.join("tool.toml");
    fs::write(&file, "new_tool = true\n").unwrap();

    let sub_target = target_dir.path().join("config").join("sub");
    fs::create_dir_all(&sub_target).unwrap();
    let existing_target = sub_target.join("tool.toml");
    fs::write(&existing_target, "old_tool = false\n").unwrap();

    let default_backup_dir = target_dir.path().join(".enstow-backup");

    let actions = vec![FileAction::Symlink {
        source: file.clone(),
        target: existing_target.clone(),
    }];

    enstow::stow::execute_plan_with_backup(
        &actions,
        false,
        None,
        false,
        true,
        Some(&default_backup_dir),
        Some(target_dir.path()),
    )
    .unwrap();

    // Preserves relative path inside backup directory
    let expected_backup = default_backup_dir
        .join("config")
        .join("sub")
        .join("tool.toml");
    assert!(expected_backup.exists());
    assert_eq!(
        fs::read_to_string(&expected_backup).unwrap(),
        "old_tool = false\n"
    );
}

#[test]
fn test_collision_existing_symlink_backed_up() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let other_dir = tempdir().unwrap();

    let file = source_dir.path().join("profile");
    fs::write(&file, "new profile").unwrap();

    let other_file = other_dir.path().join("other_profile");
    fs::write(&other_file, "external profile").unwrap();

    let existing_target = target_dir.path().join("profile");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&other_file, &existing_target).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&other_file, &existing_target).unwrap();

    let default_backup_dir = target_dir.path().join(".enstow-backup");

    let actions = vec![FileAction::Symlink {
        source: file.clone(),
        target: existing_target.clone(),
    }];

    enstow::stow::execute_plan_with_backup(
        &actions,
        false,
        None,
        false,
        true,
        Some(&default_backup_dir),
        Some(target_dir.path()),
    )
    .unwrap();

    // Target links to new source
    assert!(enstow::stow::is_symlink_to(&existing_target, &file));

    // Backup contains the previous symlink
    let backup_symlink = default_backup_dir.join("profile");
    assert!(fs::symlink_metadata(&backup_symlink)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(enstow::stow::is_symlink_to(&backup_symlink, &other_file));
}

#[test]
fn test_collision_backup_dry_run_previews_without_moving() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let file = source_dir.path().join("notes.txt");
    fs::write(&file, "new notes").unwrap();

    let existing_target = target_dir.path().join("notes.txt");
    fs::write(&existing_target, "original notes").unwrap();

    let default_backup_dir = target_dir.path().join(".enstow-backup");

    let actions = vec![FileAction::Symlink {
        source: file.clone(),
        target: existing_target.clone(),
    }];

    // Run dry_run=true
    enstow::stow::execute_plan_with_backup(
        &actions,
        true,
        None,
        false,
        true,
        Some(&default_backup_dir),
        Some(target_dir.path()),
    )
    .unwrap();

    // Disk remains untouched: target file unchanged, backup directory not created
    assert!(!default_backup_dir.exists());
    assert_eq!(
        fs::read_to_string(&existing_target).unwrap(),
        "original notes"
    );
}

#[test]
fn test_secret_collision_backed_up() {
    use age::secrecy::ExposeSecret;
    use age::Recipient;

    let temp = tempdir().unwrap();
    let key_file = temp.path().join("key.txt");
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    let source_dir = temp.path().join("source");
    let target_dir = temp.path().join("target");
    fs::create_dir_all(&source_dir).unwrap();
    fs::create_dir_all(&target_dir).unwrap();

    // Create encrypted age file
    let plaintext = b"secret_token_1234";
    let encrypted_path = source_dir.join("secret.env.age");
    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut out_file = fs::File::create(&encrypted_path).unwrap();
    let mut writer = encryptor.wrap_output(&mut out_file).unwrap();
    use std::io::Write;
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();

    // Pre-create conflicting target file
    let target_file = target_dir.join("secret.env");
    fs::write(&target_file, "old insecure token").unwrap();

    let default_backup_dir = target_dir.join(".enstow-backup");

    let actions = vec![FileAction::Decrypt {
        source: encrypted_path,
        target: target_file.clone(),
    }];

    enstow::stow::execute_plan_with_backup(
        &actions,
        false,
        Some(&key_file),
        false,
        true,
        Some(&default_backup_dir),
        Some(&target_dir),
    )
    .unwrap();

    // Target now has decrypted secret
    assert_eq!(fs::read(&target_file).unwrap(), plaintext);

    // Old token was relocated to backup
    let backup_file = default_backup_dir.join("secret.env");
    assert!(backup_file.exists());
    assert_eq!(
        fs::read_to_string(&backup_file).unwrap(),
        "old insecure token"
    );
}

#[test]
fn test_collision_backup_end_to_end_integration() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let file = source_dir.path().join("app.conf");
    fs::write(&file, "version=2.0\n").unwrap();

    let existing_target = target_dir.path().join("app.conf");
    fs::write(&existing_target, "version=1.0\n").unwrap();

    let config_path = source_dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
backup = true
"#,
    )
    .unwrap();
    let config = enstow::config::ConfigFile::load_from_path(&config_path).unwrap();

    let cli_args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        force: true,
        ..Default::default()
    };

    let resolved = enstow::config::resolve_common_args(&cli_args, Some(&config));
    assert!(resolved.backup);
    assert_eq!(
        resolved.backup_dir,
        target_dir.path().join(".enstow-backup")
    );

    let common = resolved.to_common_args();
    let plan = plan_stow(&common).unwrap();
    enstow::stow::execute_plan_with_backup(
        &plan,
        common.dry_run,
        common.age_key_file.as_deref(),
        common.force,
        common.backup,
        Some(&common.backup_dir_path()),
        Some(&common.target_path()),
    )
    .unwrap();

    // Symlinked
    assert!(enstow::stow::is_symlink_to(&existing_target, &file));

    // Backed up
    let backup_file = target_dir.path().join(".enstow-backup").join("app.conf");
    assert!(backup_file.exists());
    assert_eq!(fs::read_to_string(&backup_file).unwrap(), "version=1.0\n");
}
