use enstow::cli::CommonArgs;
use enstow::stow::{execute_unstow_plan, plan_stow};
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
        source: source_dir.path().to_path_buf(),
        target: target_dir.path().to_path_buf(),
        dry_run: false,
        force: false,
        age_key_file: None,
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

    let args = CommonArgs {
        source: source_dir.path().to_path_buf(),
        target: target_dir.path().to_path_buf(),
        dry_run: false,
        force: false,
        age_key_file: None,
    };

    let plan = plan_stow(&args).unwrap();
    execute_unstow_plan(&plan, target_dir.path(), false).unwrap();

    assert!(!target_file.exists());
    assert!(!target_dir.path().join("a").join("b").join("c").exists());
    assert!(!target_dir.path().join("a").join("b").exists());
    assert!(!target_dir.path().join("a").exists());
    assert!(target_dir.path().exists());
}
