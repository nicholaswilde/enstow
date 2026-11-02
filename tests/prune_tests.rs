use clap::Parser;
use enstow::cli::{Cli, Commands, CommonArgs};
use enstow::config::{resolve_common_args, ConfigFile, ConfigFormat};
use enstow::stow::{execute_plan, execute_unstow_plan, is_symlink_to, plan_stow};
use std::fs;
use std::sync::Mutex;
use tempfile::tempdir;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_cli_parsing_prune_flag() {
    let cli = Cli::try_parse_from(["enstow", "apply", "--prune"]).unwrap();
    match cli.command {
        Some(Commands::Apply(args)) => {
            assert!(args.prune);
        }
        other => panic!("Expected Commands::Apply, got {:?}", other),
    }

    let cli_default = Cli::try_parse_from(["enstow", "apply"]).unwrap();
    match cli_default.command {
        Some(Commands::Apply(args)) => {
            assert!(!args.prune);
        }
        other => panic!("Expected Commands::Apply, got {:?}", other),
    }
}

#[test]
fn test_config_parse_prune() {
    let toml_str = r#"
prune = true
"#;
    let yaml_str = r#"
prune: true
"#;
    let json_str = r#"{
  "prune": true
}"#;

    let cfg_toml = ConfigFile::parse(toml_str, ConfigFormat::Toml).unwrap();
    let cfg_yaml = ConfigFile::parse(yaml_str, ConfigFormat::Yaml).unwrap();
    let cfg_json = ConfigFile::parse(json_str, ConfigFormat::Json).unwrap();

    assert_eq!(cfg_toml.prune, Some(true));
    assert_eq!(cfg_toml, cfg_yaml);
    assert_eq!(cfg_yaml, cfg_json);
}

#[test]
fn test_prune_precedence_hierarchy() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let orig_prune = std::env::var("ENSTOW_PRUNE").ok();
    std::env::remove_var("ENSTOW_PRUNE");

    let empty_cli = CommonArgs::default();

    // 1. Default is false
    let resolved = resolve_common_args(&empty_cli, None);
    assert!(!resolved.prune);

    // 2. Config file sets prune = true
    let cfg = ConfigFile::parse("prune = true", ConfigFormat::Toml).unwrap();
    let resolved = resolve_common_args(&empty_cli, Some(&cfg));
    assert!(resolved.prune);

    // 3. Env var ENSTOW_PRUNE overrides config file
    // 3a. Env disables prune with "0" / "false"
    std::env::set_var("ENSTOW_PRUNE", "0");
    let resolved = resolve_common_args(&empty_cli, Some(&cfg));
    assert!(!resolved.prune);

    std::env::set_var("ENSTOW_PRUNE", "false");
    let resolved = resolve_common_args(&empty_cli, Some(&cfg));
    assert!(!resolved.prune);

    // 3b. Env enables prune with "1" / "true" over config false
    let cfg_false = ConfigFile::parse("prune = false", ConfigFormat::Toml).unwrap();
    std::env::set_var("ENSTOW_PRUNE", "1");
    let resolved = resolve_common_args(&empty_cli, Some(&cfg_false));
    assert!(resolved.prune);

    std::env::set_var("ENSTOW_PRUNE", "true");
    let resolved = resolve_common_args(&empty_cli, Some(&cfg_false));
    assert!(resolved.prune);

    // 4. CLI flag --prune overrides env and config
    std::env::set_var("ENSTOW_PRUNE", "0");
    let cli_flag = CommonArgs {
        prune: true,
        ..Default::default()
    };
    let resolved = resolve_common_args(&cli_flag, Some(&cfg_false));
    assert!(resolved.prune);

    std::env::remove_var("ENSTOW_PRUNE");
    if let Some(v) = orig_prune {
        std::env::set_var("ENSTOW_PRUNE", v);
    }
}

#[test]
fn test_apply_with_prune_removes_stale_symlinks() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

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

    // Remove file2 from source
    fs::remove_file(&file2).unwrap();

    // 1. Apply without prune: stale link remains
    let apply_no_prune = plan_stow(&args).unwrap();
    execute_plan(&apply_no_prune, false, None, false).unwrap();
    assert!(fs::symlink_metadata(&target_file2).is_ok());

    // 2. Apply with prune: plan_prune finds and removes target_file2
    let prune_args = CommonArgs {
        prune: true,
        ..args.clone()
    };
    let stale_actions = enstow::stow::plan_prune(&prune_args).unwrap();
    assert_eq!(stale_actions.len(), 1);
    assert_eq!(
        enstow::stow::normalize_path(stale_actions[0].target()),
        enstow::stow::normalize_path(&target_file2)
    );

    execute_unstow_plan(
        &stale_actions,
        &prune_args.target_path(),
        prune_args.dry_run,
    )
    .unwrap();
    let apply_plan = plan_stow(&prune_args).unwrap();
    execute_plan(&apply_plan, prune_args.dry_run, None, prune_args.force).unwrap();

    assert!(fs::symlink_metadata(&target_file2).is_err());
    assert!(target_file1.exists());
    assert!(is_symlink_to(&target_file1, &file1));
}

#[test]
fn test_apply_with_prune_dry_run_previews_without_deleting() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let pkg_dir = source_dir.path().join("pkg");
    fs::create_dir_all(&pkg_dir).unwrap();
    let file1 = pkg_dir.join("live.txt");
    let file2 = pkg_dir.join("stale.txt");
    fs::write(&file1, "1\n").unwrap();
    fs::write(&file2, "2\n").unwrap();

    let _target_file1 = target_dir.path().join("live.txt");
    let target_file2 = target_dir.path().join("stale.txt");

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: false,
        force: false,
        prune: false,
        age_key_file: None,
        packages: vec!["pkg".to_string()],
        ignore: Vec::new(),
        ..Default::default()
    };

    let initial_plan = plan_stow(&args).unwrap();
    execute_plan(&initial_plan, false, None, false).unwrap();

    fs::remove_file(&file2).unwrap();

    let dry_prune_args = CommonArgs {
        dry_run: true,
        prune: true,
        ..args
    };

    let stale_actions = enstow::stow::plan_prune(&dry_prune_args).unwrap();
    assert_eq!(stale_actions.len(), 1);
    execute_unstow_plan(
        &stale_actions,
        &dry_prune_args.target_path(),
        dry_prune_args.dry_run,
    )
    .unwrap();

    let apply_plan = plan_stow(&dry_prune_args).unwrap();
    execute_plan(
        &apply_plan,
        dry_prune_args.dry_run,
        None,
        dry_prune_args.force,
    )
    .unwrap();

    // In dry-run, stale link is not deleted
    assert!(fs::symlink_metadata(&target_file2).is_ok());
}

#[test]
fn test_apply_with_prune_via_config_and_env() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let orig_prune = std::env::var("ENSTOW_PRUNE").ok();
    std::env::remove_var("ENSTOW_PRUNE");

    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let pkg_dir = source_dir.path().join("my_pkg");
    fs::create_dir_all(&pkg_dir).unwrap();
    let file1 = pkg_dir.join("live.txt");
    let file2 = pkg_dir.join("stale.txt");
    fs::write(&file1, "live\n").unwrap();
    fs::write(&file2, "stale\n").unwrap();

    let target_file1 = target_dir.path().join("live.txt");
    let target_file2 = target_dir.path().join("stale.txt");

    let cli_args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        packages: vec!["my_pkg".to_string()],
        ..Default::default()
    };

    // Initial stow
    let initial_resolved = resolve_common_args(&cli_args, None).to_common_args();
    let initial_plan = plan_stow(&initial_resolved).unwrap();
    execute_plan(&initial_plan, false, None, false).unwrap();
    assert!(target_file1.exists());
    assert!(target_file2.exists());

    // Remove file2 from source
    fs::remove_file(&file2).unwrap();

    // 1. With config prune = true
    let cfg = ConfigFile::parse("prune = true", ConfigFormat::Toml).unwrap();
    let resolved_cfg = resolve_common_args(&cli_args, Some(&cfg)).to_common_args();
    assert!(resolved_cfg.prune);

    let stale_actions = enstow::stow::plan_prune(&resolved_cfg).unwrap();
    assert_eq!(stale_actions.len(), 1);
    execute_unstow_plan(
        &stale_actions,
        &resolved_cfg.target_path(),
        resolved_cfg.dry_run,
    )
    .unwrap();
    assert!(fs::symlink_metadata(&target_file2).is_err());

    // Recreate stale symlink to test ENSTOW_PRUNE=1
    #[cfg(unix)]
    std::os::unix::fs::symlink(&file2, &target_file2).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&file2, &target_file2).unwrap();
    assert!(fs::symlink_metadata(&target_file2).is_ok());

    // 2. With ENSTOW_PRUNE=1 over config prune = false
    let cfg_false = ConfigFile::parse("prune = false", ConfigFormat::Toml).unwrap();
    std::env::set_var("ENSTOW_PRUNE", "1");
    let resolved_env = resolve_common_args(&cli_args, Some(&cfg_false)).to_common_args();
    assert!(resolved_env.prune);

    let stale_actions2 = enstow::stow::plan_prune(&resolved_env).unwrap();
    assert_eq!(stale_actions2.len(), 1);
    execute_unstow_plan(
        &stale_actions2,
        &resolved_env.target_path(),
        resolved_env.dry_run,
    )
    .unwrap();
    assert!(fs::symlink_metadata(&target_file2).is_err());

    std::env::remove_var("ENSTOW_PRUNE");
    if let Some(v) = orig_prune {
        std::env::set_var("ENSTOW_PRUNE", v);
    }
}

#[test]
fn test_plan_prune_relative_stale_symlink() {
    let parent = tempdir().unwrap();
    let source_dir = parent.path().join("src");
    let target_dir = parent.path().join("dst");
    let pkg_dir = source_dir.join("pkg");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::create_dir_all(&target_dir).unwrap();

    let file = pkg_dir.join("test.txt");
    fs::write(&file, "test").unwrap();

    let target_link = target_dir.join("test.txt");
    let rel = std::path::Path::new("..")
        .join("src")
        .join("pkg")
        .join("test.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&rel, &target_link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&rel, &target_link).unwrap();

    // Now remove file from source so it becomes stale
    fs::remove_file(&file).unwrap();

    let args = CommonArgs {
        source: Some(source_dir),
        target: Some(target_dir),
        packages: vec!["pkg".to_string()],
        prune: true,
        ..Default::default()
    };

    let stale_actions = enstow::stow::plan_prune(&args).unwrap();
    assert_eq!(stale_actions.len(), 1);
    assert_eq!(stale_actions[0].target(), target_link.as_path());
}
