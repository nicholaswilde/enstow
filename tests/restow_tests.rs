use age::secrecy::ExposeSecret;
use age::Recipient;
use clap::Parser;
use enstow::cli::{Cli, Commands, CommonArgs};
use enstow::stow::{
    check_status, execute_plan, execute_plan_with_backup, execute_unstow_plan, is_symlink_to,
    plan_stow, plan_unstow, EntryStatus,
};
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

fn create_dir_symlink(src: &std::path::Path, dst: &std::path::Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(src, dst).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(src, dst).unwrap();
}

#[test]
fn test_folded_dir_symlink_unfolded_safely_on_apply_dry_run_and_force() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let pkg_nvim = source_dir.path().join("nvim").join(".config").join("nvim");
    let pkg_lua = pkg_nvim.join("lua");
    fs::create_dir_all(&pkg_lua).unwrap();
    let init_src = pkg_nvim.join("init.lua");
    let plugins_src = pkg_lua.join("plugins.lua");
    fs::write(&init_src, "-- init\n").unwrap();
    fs::write(&plugins_src, "-- plugins\n").unwrap();

    // Legacy GNU Stow folded directory symlink: ~/.config/nvim -> repo/nvim/.config/nvim
    let target_config = target_dir.path().join(".config");
    fs::create_dir_all(&target_config).unwrap();
    let folded_nvim = target_config.join("nvim");
    create_dir_symlink(&pkg_nvim, &folded_nvim);

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        packages: vec!["nvim".to_string()],
        ..Default::default()
    };
    let actions = plan_stow(&args).unwrap();
    assert_eq!(actions.len(), 2);

    // 1. status reports Conflict for files behind a folded directory symlink
    let statuses = check_status(&actions, None).unwrap();
    assert!(statuses.iter().all(|s| s.status == EntryStatus::Conflict));

    // 2. dry-run succeeds without mutating the folded symlink or source files
    execute_plan_with_backup(
        &actions,
        true,
        None,
        false,
        false,
        None,
        Some(target_dir.path()),
    )
    .unwrap();
    assert!(fs::symlink_metadata(&folded_nvim)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_to_string(&init_src).unwrap(), "-- init\n");

    // 3. apply (without --force) unfolds folded symlink into real dir and creates per-file symlinks
    execute_plan_with_backup(
        &actions,
        false,
        None,
        false,
        false,
        None,
        Some(target_dir.path()),
    )
    .unwrap();
    let folded_meta = fs::symlink_metadata(&folded_nvim).unwrap();
    assert!(
        folded_meta.file_type().is_dir() && !folded_meta.file_type().is_symlink(),
        "expected unfolded real directory at {}",
        folded_nvim.display()
    );
    assert!(is_symlink_to(&folded_nvim.join("init.lua"), &init_src));
    assert!(is_symlink_to(
        &folded_nvim.join("lua").join("plugins.lua"),
        &plugins_src
    ));
    // Original source files inside repo remain intact regular files
    assert!(!fs::symlink_metadata(&init_src)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_to_string(&init_src).unwrap(), "-- init\n");
    assert_eq!(fs::read_to_string(&plugins_src).unwrap(), "-- plugins\n");

    let synced_statuses = check_status(&actions, None).unwrap();
    assert!(synced_statuses
        .iter()
        .all(|s| s.status == EntryStatus::Synced));

    // 4. apply --force on a folded symlink also unfolds safely without destroying source files
    fs::remove_dir_all(&folded_nvim).unwrap();
    create_dir_symlink(&pkg_nvim, &folded_nvim);
    execute_plan_with_backup(
        &actions,
        false,
        None,
        true,
        false,
        None,
        Some(target_dir.path()),
    )
    .unwrap();
    assert!(fs::symlink_metadata(&folded_nvim)
        .unwrap()
        .file_type()
        .is_dir());
    assert!(!fs::symlink_metadata(&init_src)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_to_string(&init_src).unwrap(), "-- init\n");
    assert!(is_symlink_to(&folded_nvim.join("init.lua"), &init_src));
}

#[test]
fn test_folded_dir_symlink_with_encrypted_secret_and_restow() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    let key_file = key_dir.path().join("keys.txt");
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    let pkg_pvetui = source_dir
        .path()
        .join("pvetui")
        .join(".config")
        .join("pvetui");
    fs::create_dir_all(&pkg_pvetui).unwrap();
    let secret_src = pkg_pvetui.join("config.yml.age");
    let plaintext = b"api_token: super-secret\n";
    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    fs::write(&secret_src, encrypted).unwrap();

    // Legacy folded symlink pointing into secret package dir
    let target_config = target_dir.path().join(".config");
    fs::create_dir_all(&target_config).unwrap();
    let folded_pvetui = target_config.join("pvetui");
    create_dir_symlink(&pkg_pvetui, &folded_pvetui);

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_file.clone()),
        packages: vec!["pvetui".to_string()],
        ..Default::default()
    };

    // status flags Conflict for secret behind folded dir symlink
    let actions = plan_stow(&args).unwrap();
    let statuses = check_status(&actions, Some(&key_file)).unwrap();
    assert_eq!(statuses[0].status, EntryStatus::Conflict);

    // apply unfolds directory symlink and writes decrypted secret ONLY in target, NEVER in repo
    execute_plan_with_backup(
        &actions,
        false,
        Some(&key_file),
        false,
        false,
        None,
        Some(target_dir.path()),
    )
    .unwrap();
    assert!(fs::symlink_metadata(&folded_pvetui)
        .unwrap()
        .file_type()
        .is_dir());
    assert_eq!(
        fs::read(folded_pvetui.join("config.yml")).unwrap(),
        plaintext
    );
    assert!(
        !pkg_pvetui.join("config.yml").exists(),
        "plaintext secret must never be written into source repo"
    );

    // restow from a folded directory symlink also unfolds cleanly
    fs::remove_dir_all(&folded_pvetui).unwrap();
    create_dir_symlink(&pkg_pvetui, &folded_pvetui);

    let unstow_actions = plan_unstow(&args).unwrap();
    execute_unstow_plan(&unstow_actions, target_dir.path(), false).unwrap();
    let apply_actions = plan_stow(&args).unwrap();
    execute_plan_with_backup(
        &apply_actions,
        false,
        Some(&key_file),
        false,
        false,
        None,
        Some(target_dir.path()),
    )
    .unwrap();

    assert!(fs::symlink_metadata(&folded_pvetui)
        .unwrap()
        .file_type()
        .is_dir());
    assert_eq!(
        fs::read(folded_pvetui.join("config.yml")).unwrap(),
        plaintext
    );
    assert!(!pkg_pvetui.join("config.yml").exists());
}

#[test]
fn test_unrelated_dir_symlink_is_not_unfolded() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let external_dir = tempdir().unwrap();

    let pkg_dir = source_dir.path().join("app").join(".config").join("app");
    fs::create_dir_all(&pkg_dir).unwrap();
    let src_conf = pkg_dir.join("app.conf");
    fs::write(&src_conf, "ok=1\n").unwrap();

    let target_config = target_dir.path().join(".config");
    fs::create_dir_all(&target_config).unwrap();
    let custom_link = target_config.join("app");
    create_dir_symlink(external_dir.path(), &custom_link);

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        packages: vec!["app".to_string()],
        ..Default::default()
    };
    let actions = plan_stow(&args).unwrap();
    execute_plan_with_backup(
        &actions,
        false,
        None,
        false,
        false,
        None,
        Some(target_dir.path()),
    )
    .unwrap();

    // Unrelated directory symlink pointing outside source remains untouched
    assert!(fs::symlink_metadata(&custom_link)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(is_symlink_to(&custom_link.join("app.conf"), &src_conf));
}

#[test]
fn test_safety_guard_refuses_modifying_target_inside_source_dir() {
    let dir = tempdir().unwrap();
    let src_file = dir.path().join(".bashrc");
    fs::write(&src_file, "export SAFE=1\n").unwrap();

    // Target resolves to the same directory as source (e.g. source == target)
    let args = CommonArgs {
        source: Some(dir.path().to_path_buf()),
        target: Some(dir.path().to_path_buf()),
        force: true,
        ..Default::default()
    };
    let actions = plan_stow(&args).unwrap();
    let err = execute_plan(&actions, false, None, true).unwrap_err();
    assert!(
        err.to_string().contains("resolves to source directory"),
        "unexpected error: {err}"
    );
    // Original file inside source must remain completely intact
    assert_eq!(fs::read_to_string(&src_file).unwrap(), "export SAFE=1\n");
}
