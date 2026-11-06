use enstow::cli::{Cli, Commands, CommonArgs};
use enstow::config::resolve_common_args;
use enstow::stow::{
    execute_unstow_plan, execute_unstow_plan_with_shred, plan_stow, shred_file, zeroize_file,
};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_unstow_removes_matching_symlinks_and_decrypted_secrets() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Setup source files
    let config_dir = source_dir.path().join(".config").join("app");
    fs::create_dir_all(&config_dir).unwrap();
    let config_file = config_dir.join("config.toml");
    fs::write(&config_file, "setting = true\n").unwrap();

    let secret_file = config_dir.join("secret.age");
    fs::write(&secret_file, "fake_age_payload").unwrap();

    // Setup target files
    let target_app_dir = target_dir.path().join(".config").join("app");
    fs::create_dir_all(&target_app_dir).unwrap();

    // 1. Target symlink pointing back to source config
    let target_symlink = target_app_dir.join("config.toml");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&config_file, &target_symlink).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&config_file, &target_symlink).unwrap();

    // 2. Target decrypted plaintext secret
    let target_secret = target_app_dir.join("secret");
    fs::write(&target_secret, "decrypted_secret_data").unwrap();

    // 3. Unrelated file that must NOT be removed
    let unrelated_file = target_dir
        .path()
        .join(".config")
        .join("app")
        .join("other.txt");
    fs::write(&unrelated_file, "do not touch").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: false,
        force: false,
        prune: false,
        age_key_file: None,
        packages: Vec::new(),
        ignore: Vec::new(),
        ..Default::default()
    };

    let plan = plan_stow(&args).unwrap();

    // Dry-run should not remove anything
    execute_unstow_plan(&plan, target_dir.path(), true).unwrap();
    assert!(target_symlink.exists());
    assert!(target_secret.exists());
    assert!(unrelated_file.exists());

    // Real execution
    execute_unstow_plan(&plan, target_dir.path(), false).unwrap();

    // Target symlink and managed secret should be removed
    assert!(!target_symlink.exists());
    assert!(!target_secret.exists());

    // Unrelated file remains
    assert!(unrelated_file.exists());
    // Directory is not empty, so it remains
    assert!(target_app_dir.exists());
}

#[test]
fn test_unstow_cleans_empty_parent_directories() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let nested_dir = source_dir.path().join("a").join("b").join("c");
    fs::create_dir_all(&nested_dir).unwrap();
    let file = nested_dir.join("file.txt");
    fs::write(&file, "test").unwrap();

    let target_file = target_dir
        .path()
        .join("a")
        .join("b")
        .join("c")
        .join("file.txt");
    fs::create_dir_all(target_file.parent().unwrap()).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&file, &target_file).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&file, &target_file).unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: false,
        force: false,
        prune: false,
        age_key_file: None,
        packages: Vec::new(),
        ignore: Vec::new(),
        ..Default::default()
    };

    let plan = plan_stow(&args).unwrap();
    execute_unstow_plan(&plan, target_dir.path(), false).unwrap();

    assert!(!target_file.exists());
    assert!(!target_dir.path().join("a").join("b").join("c").exists());
    assert!(!target_dir.path().join("a").join("b").exists());
    assert!(!target_dir.path().join("a").exists());
    assert!(target_dir.path().exists());
}

#[test]
fn test_zeroize_file_overwrites_with_zeros() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("secret.txt");
    let secret_data = b"super_secret_payload_12345";
    fs::write(&file, secret_data).unwrap();

    assert!(file.exists());
    assert_eq!(fs::read(&file).unwrap(), secret_data);

    zeroize_file(&file).unwrap();

    assert!(file.exists());
    assert_eq!(fs::metadata(&file).unwrap().len(), secret_data.len() as u64);
    assert_eq!(fs::read(&file).unwrap(), vec![0u8; secret_data.len()]);
}

#[test]
fn test_shred_file_removes_file_after_zeroing() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("secret.txt");
    fs::write(&file, b"confidential_data").unwrap();

    assert!(file.exists());
    shred_file(&file).unwrap();

    assert!(fs::symlink_metadata(&file).is_err());
}

#[test]
fn test_unstow_with_shred_execution() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let config_dir = source_dir.path().join(".config").join("app");
    fs::create_dir_all(&config_dir).unwrap();
    let secret_file = config_dir.join("secret.age");
    fs::write(&secret_file, "fake_age_payload").unwrap();

    let target_app_dir = target_dir.path().join(".config").join("app");
    fs::create_dir_all(&target_app_dir).unwrap();
    let target_secret = target_app_dir.join("secret");
    fs::write(&target_secret, "decrypted_secret_data").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: false,
        force: false,
        prune: false,
        shred: true,
        age_key_file: None,
        packages: Vec::new(),
        ignore: Vec::new(),
        ..Default::default()
    };

    let plan = plan_stow(&args).unwrap();

    // Dry-run should not remove the file
    execute_unstow_plan_with_shred(&plan, target_dir.path(), true, true).unwrap();
    assert!(target_secret.exists());

    // Real execution with shred
    execute_unstow_plan_with_shred(&plan, target_dir.path(), false, true).unwrap();
    assert!(fs::symlink_metadata(&target_secret).is_err());
}

#[test]
fn test_unstow_cli_shred_flag_and_config() {
    use clap::Parser;

    // 1. CLI flag on unstow
    let cli = Cli::try_parse_from(["enstow", "unstow", "--shred", "pkg1"]).unwrap();
    match cli.command {
        Some(Commands::Unstow(args)) => {
            assert!(args.shred);
        }
        _ => panic!("Expected Unstow command"),
    }

    // 2. Standalone scrub command
    let cli_scrub = Cli::try_parse_from(["enstow", "scrub", "pkg1"]).unwrap();
    match cli_scrub.command {
        Some(Commands::Scrub(args)) => {
            assert_eq!(args.packages, vec!["pkg1".to_string()]);
        }
        _ => panic!("Expected Scrub command"),
    }

    // 3. Config resolution: shred = true in ConfigFile
    let config_toml = r#"
shred = true
"#;
    let config: enstow::config::ConfigFile = toml::from_str(config_toml).unwrap();
    let args = CommonArgs::default();
    let resolved = resolve_common_args(&args, Some(&config)).unwrap();
    assert!(resolved.shred);
    assert!(resolved.to_common_args().shred);
}
