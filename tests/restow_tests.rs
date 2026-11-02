use age::secrecy::ExposeSecret;
use age::Recipient;
use clap::Parser;
use enstow::cli::{Cli, Commands, CommonArgs};
use enstow::stow::{execute_plan, execute_unstow_plan, is_symlink_to, plan_stow, plan_unstow};
use std::fs;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_cli_parsing_restow() {
    // 1. restow with packages and flags
    let cli = Cli::try_parse_from([
        "enstow",
        "restow",
        "--dry-run",
        "--force",
        "-s",
        "/custom/source",
        "-t",
        "/custom/target",
        "zsh",
        "nvim",
    ])
    .unwrap();

    match cli.command {
        Some(Commands::Restow(args)) => {
            assert!(args.dry_run);
            assert!(args.force);
            assert_eq!(
                args.source,
                Some(std::path::PathBuf::from("/custom/source"))
            );
            assert_eq!(
                args.target,
                Some(std::path::PathBuf::from("/custom/target"))
            );
            assert_eq!(args.packages, vec!["zsh", "nvim"]);
        }
        other => panic!("Expected Commands::Restow, got {:?}", other),
    }

    // 2. restow with no packages (whole source)
    let cli = Cli::try_parse_from(["enstow", "restow"]).unwrap();
    match cli.command {
        Some(Commands::Restow(args)) => {
            assert!(args.packages.is_empty());
            assert!(!args.dry_run);
        }
        other => panic!("Expected Commands::Restow, got {:?}", other),
    }
}

#[test]
fn test_restow_prunes_removed_dotfile() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Setup package with two files
    let pkg_dir = source_dir.path().join("my_pkg");
    fs::create_dir_all(&pkg_dir).unwrap();
    let file1 = pkg_dir.join("kept.txt");
    let file2 = pkg_dir.join("stale.txt");
    fs::write(&file1, "keep this\n").unwrap();
    fs::write(&file2, "delete this\n").unwrap();

    let target_file1 = target_dir.path().join("kept.txt");
    let target_file2 = target_dir.path().join("stale.txt");

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: false,
        force: false,
        prune: false,
        age_key_file: None,
        packages: vec!["my_pkg".to_string()],
        ignore: Vec::new(),
        ..Default::default()
    };

    // Initial stow
    let initial_plan = plan_stow(&args).unwrap();
    execute_plan(&initial_plan, false, None, false).unwrap();
    assert!(target_file1.exists());
    assert!(target_file2.exists());
    assert!(is_symlink_to(&target_file1, &file1));
    assert!(is_symlink_to(&target_file2, &file2));

    // Remove file2 from source package
    fs::remove_file(&file2).unwrap();

    // Execute restow: plan_unstow followed by execute_unstow_plan, then plan_stow and execute_plan
    let unstow_plan = plan_unstow(&args).unwrap();
    execute_unstow_plan(&unstow_plan, target_dir.path(), false).unwrap();

    let apply_plan = plan_stow(&args).unwrap();
    execute_plan(&apply_plan, false, None, false).unwrap();

    // Verify stale file was pruned and kept file remains linked
    assert!(fs::symlink_metadata(&target_file2).is_err());
    assert!(target_file1.exists());
    assert!(is_symlink_to(&target_file1, &file1));
}

#[test]
fn test_restow_prunes_removed_nested_directory() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let pkg_dir = source_dir.path().join("app");
    let nested_dir = pkg_dir.join(".config").join("app").join("sub");
    fs::create_dir_all(&nested_dir).unwrap();

    let kept_file = pkg_dir.join(".config").join("app").join("config.toml");
    let stale_file = nested_dir.join("old.toml");
    fs::write(&kept_file, "setting = 1\n").unwrap();
    fs::write(&stale_file, "old = true\n").unwrap();

    let target_kept = target_dir
        .path()
        .join(".config")
        .join("app")
        .join("config.toml");
    let target_stale = target_dir
        .path()
        .join(".config")
        .join("app")
        .join("sub")
        .join("old.toml");
    let target_nested_dir = target_dir.path().join(".config").join("app").join("sub");

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: false,
        force: false,
        prune: false,
        age_key_file: None,
        packages: vec!["app".to_string()],
        ignore: Vec::new(),
        ..Default::default()
    };

    let initial_plan = plan_stow(&args).unwrap();
    execute_plan(&initial_plan, false, None, false).unwrap();
    assert!(target_kept.exists());
    assert!(target_stale.exists());

    // Remove stale file and sub directory from package
    fs::remove_file(&stale_file).unwrap();
    fs::remove_dir(&nested_dir).unwrap();

    // Restow
    let unstow_plan = plan_unstow(&args).unwrap();
    execute_unstow_plan(&unstow_plan, target_dir.path(), false).unwrap();

    let apply_plan = plan_stow(&args).unwrap();
    execute_plan(&apply_plan, false, None, false).unwrap();

    // target_stale and empty target_nested_dir pruned
    assert!(fs::symlink_metadata(&target_stale).is_err());
    assert!(!target_nested_dir.exists());

    // target_kept preserved
    assert!(target_kept.exists());
    assert!(is_symlink_to(&target_kept, &kept_file));
}

#[test]
fn test_restow_dry_run_does_not_modify_disk() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let pkg_dir = source_dir.path().join("app");
    fs::create_dir_all(&pkg_dir).unwrap();
    let file1 = pkg_dir.join("file1.txt");
    let file2 = pkg_dir.join("file2.txt");
    fs::write(&file1, "1\n").unwrap();
    fs::write(&file2, "2\n").unwrap();

    let target_file1 = target_dir.path().join("file1.txt");
    let target_file2 = target_dir.path().join("file2.txt");

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: false,
        force: false,
        prune: false,
        age_key_file: None,
        packages: vec!["app".to_string()],
        ignore: Vec::new(),
        ..Default::default()
    };

    let initial_plan = plan_stow(&args).unwrap();
    execute_plan(&initial_plan, false, None, false).unwrap();

    // Remove file2 in source
    fs::remove_file(&file2).unwrap();

    let dry_args = CommonArgs {
        dry_run: true,
        ..args
    };

    let unstow_plan = plan_unstow(&dry_args).unwrap();
    execute_unstow_plan(&unstow_plan, target_dir.path(), true).unwrap();

    let apply_plan = plan_stow(&dry_args).unwrap();
    execute_plan(&apply_plan, true, None, false).unwrap();

    // Both files must still exist as symlinks because dry_run was true
    assert!(fs::symlink_metadata(&target_file1).is_ok());
    assert!(fs::symlink_metadata(&target_file2).is_ok());
}

#[test]
fn test_restow_with_mixed_regular_and_age_files() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let pkg_dir = source_dir.path().join("mixed");
    fs::create_dir_all(&pkg_dir).unwrap();
    let conf_file = pkg_dir.join("app.conf");
    fs::write(&conf_file, "verbose = true\n").unwrap();

    let secret_age = pkg_dir.join("token.age");
    let key_dir = tempdir().unwrap();
    let key_file = key_dir.path().join("key.txt");
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    let plaintext = b"SECRET_VALUE_123\n";
    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    fs::write(&secret_age, encrypted_buf).unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: false,
        force: false,
        prune: false,
        age_key_file: Some(key_file.clone()),
        packages: vec!["mixed".to_string()],
        ignore: Vec::new(),
        ..Default::default()
    };

    // Initial stow
    let initial_plan = plan_stow(&args).unwrap();
    execute_plan(&initial_plan, false, Some(&key_file), false).unwrap();

    let target_conf = target_dir.path().join("app.conf");
    let target_secret = target_dir.path().join("token");
    assert!(target_conf.exists());
    assert!(target_secret.exists());

    // Restow
    let unstow_plan = plan_unstow(&args).unwrap();
    execute_unstow_plan(&unstow_plan, target_dir.path(), false).unwrap();

    let apply_plan = plan_stow(&args).unwrap();
    execute_plan(&apply_plan, false, Some(&key_file), false).unwrap();

    assert!(target_conf.exists());
    assert!(is_symlink_to(&target_conf, &conf_file));
    assert!(target_secret.exists());
    assert_eq!(fs::read(&target_secret).unwrap(), plaintext);
}
