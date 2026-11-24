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
    let resolved = resolve_common_args(&empty_cli, None).unwrap();
    assert!(!resolved.prune);

    // 2. Config file sets prune = true
    let cfg = ConfigFile::parse("prune = true", ConfigFormat::Toml).unwrap();
    let resolved = resolve_common_args(&empty_cli, Some(&cfg)).unwrap();
    assert!(resolved.prune);

    // 3. Env var ENSTOW_PRUNE overrides config file
    // 3a. Env disables prune with "0" / "false"
    std::env::set_var("ENSTOW_PRUNE", "0");
    let resolved = resolve_common_args(&empty_cli, Some(&cfg)).unwrap();
    assert!(!resolved.prune);

    std::env::set_var("ENSTOW_PRUNE", "false");
    let resolved = resolve_common_args(&empty_cli, Some(&cfg)).unwrap();
    assert!(!resolved.prune);

    // 3b. Env enables prune with "1" / "true" over config false
    let cfg_false = ConfigFile::parse("prune = false", ConfigFormat::Toml).unwrap();
    std::env::set_var("ENSTOW_PRUNE", "1");
    let resolved = resolve_common_args(&empty_cli, Some(&cfg_false)).unwrap();
    assert!(resolved.prune);

    std::env::set_var("ENSTOW_PRUNE", "true");
    let resolved = resolve_common_args(&empty_cli, Some(&cfg_false)).unwrap();
    assert!(resolved.prune);

    // 4. CLI flag --prune overrides env and config
    std::env::set_var("ENSTOW_PRUNE", "0");
    let cli_flag = CommonArgs {
        prune: true,
        ..Default::default()
    };
    let resolved = resolve_common_args(&cli_flag, Some(&cfg_false)).unwrap();
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
    let initial_resolved = resolve_common_args(&cli_args, None)
        .unwrap()
        .to_common_args();
    let initial_plan = plan_stow(&initial_resolved).unwrap();
    execute_plan(&initial_plan, false, None, false).unwrap();
    assert!(target_file1.exists());
    assert!(target_file2.exists());

    // Remove file2 from source
    fs::remove_file(&file2).unwrap();

    // 1. With config prune = true
    let cfg = ConfigFile::parse("prune = true", ConfigFormat::Toml).unwrap();
    let resolved_cfg = resolve_common_args(&cli_args, Some(&cfg))
        .unwrap()
        .to_common_args();
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
    let resolved_env = resolve_common_args(&cli_args, Some(&cfg_false))
        .unwrap()
        .to_common_args();
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

#[test]
fn test_cli_parsing_default_no_subcommand_prune_flag() {
    let cli = Cli::try_parse_from(["enstow", "--prune"]).unwrap();
    assert!(cli.command.is_none());
    assert!(cli.common.prune);

    let cli_default = Cli::try_parse_from(["enstow"]).unwrap();
    assert!(cli_default.command.is_none());
    assert!(!cli_default.common.prune);
}

#[test]
fn test_plan_prune_deeply_nested_depth_6_and_managed_ignored_dir() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Realistic agy-config layout at depth 6 under $TARGET/.gemini (a dir also in is_stale_scan_ignored_dir)
    let skill_dir = source_dir
        .path()
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("demo-skill");
    let scripts_dir = skill_dir.join("scripts");
    let agents_dir = skill_dir.join("agents");
    fs::create_dir_all(&scripts_dir).unwrap();
    fs::create_dir_all(&agents_dir).unwrap();

    let kept_skill_md = skill_dir.join("SKILL.md"); // depth 5
    let stale_script = scripts_dir.join("old.sh"); // depth 6
    let stale_agent = agents_dir.join("openai.yaml"); // depth 6
    let stale_top_level = source_dir.path().join(".oldrc"); // depth 1

    fs::write(&kept_skill_md, "# demo\n").unwrap();
    fs::write(&stale_script, "#!/bin/sh\necho old\n").unwrap();
    fs::write(&stale_agent, "name: demo\n").unwrap();
    fs::write(&stale_top_level, "export OLD=1\n").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        prune: true,
        ..Default::default()
    };

    // Initial stow
    let initial_plan = plan_stow(&args).unwrap();
    execute_plan(&initial_plan, false, None, false).unwrap();

    let target_kept = target_dir
        .path()
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("demo-skill")
        .join("SKILL.md");
    let target_stale_script = target_dir
        .path()
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("demo-skill")
        .join("scripts")
        .join("old.sh");
    let target_stale_agent = target_dir
        .path()
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("demo-skill")
        .join("agents")
        .join("openai.yaml");
    let target_stale_top = target_dir.path().join(".oldrc");

    assert!(is_symlink_to(&target_kept, &kept_skill_md));
    assert!(is_symlink_to(&target_stale_script, &stale_script));
    assert!(is_symlink_to(&target_stale_agent, &stale_agent));
    assert!(is_symlink_to(&target_stale_top, &stale_top_level));

    // Ignored dir inside managed subtree must still be skipped by stale scan
    let ignored_node_modules = target_dir
        .path()
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("demo-skill")
        .join("node_modules");
    fs::create_dir_all(&ignored_node_modules).unwrap();
    let ignored_stale = ignored_node_modules.join("ignored_link");
    let phantom_src = source_dir.path().join("phantom_in_node_modules");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&phantom_src, &ignored_stale).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&phantom_src, &ignored_stale).unwrap();

    // Remove depth-6 files, their empty source subdirs, and depth-1 top-level file
    fs::remove_file(&stale_script).unwrap();
    fs::remove_dir(&scripts_dir).unwrap();
    fs::remove_file(&stale_agent).unwrap();
    fs::remove_dir(&agents_dir).unwrap();
    fs::remove_file(&stale_top_level).unwrap();

    let stale_actions = enstow::stow::plan_prune(&args).unwrap();
    let stale_targets: Vec<_> = stale_actions
        .iter()
        .map(|a| enstow::stow::normalize_path(a.target()))
        .collect();

    assert_eq!(
        stale_targets.len(),
        3,
        "Expected 2 depth-6 stale symlinks and 1 top-level stale symlink, got: {:?}",
        stale_targets
    );
    assert!(stale_targets.contains(&enstow::stow::normalize_path(&target_stale_script)));
    assert!(stale_targets.contains(&enstow::stow::normalize_path(&target_stale_agent)));
    assert!(stale_targets.contains(&enstow::stow::normalize_path(&target_stale_top)));
    assert!(!stale_targets.contains(&enstow::stow::normalize_path(&ignored_stale)));

    execute_unstow_plan(&stale_actions, &args.target_path(), false).unwrap();

    assert!(fs::symlink_metadata(&target_stale_script).is_err());
    assert!(fs::symlink_metadata(&target_stale_agent).is_err());
    assert!(fs::symlink_metadata(&target_stale_top).is_err());
    assert!(fs::symlink_metadata(&ignored_stale).is_ok());
    assert!(is_symlink_to(&target_kept, &kept_skill_md));
}

#[test]
fn test_plan_prune_depth_6_when_package_becomes_empty() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let pkg_dir = source_dir.path().join("deep_pkg");
    let deep_parent = pkg_dir
        .join(".config")
        .join("a")
        .join("b")
        .join("c")
        .join("d");
    fs::create_dir_all(&deep_parent).unwrap();
    let deep_file = deep_parent.join("only.txt"); // depth 6 under target
    fs::write(&deep_file, "deep\n").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        packages: vec!["deep_pkg".to_string()],
        prune: true,
        ..Default::default()
    };

    let initial_plan = plan_stow(&args).unwrap();
    execute_plan(&initial_plan, false, None, false).unwrap();

    let target_deep = target_dir
        .path()
        .join(".config")
        .join("a")
        .join("b")
        .join("c")
        .join("d")
        .join("only.txt");
    assert!(is_symlink_to(&target_deep, &deep_file));

    // Delete file and its entire nested tree so package is completely empty
    fs::remove_dir_all(pkg_dir.join(".config")).unwrap();

    let stale_actions = enstow::stow::plan_prune(&args).unwrap();
    assert_eq!(stale_actions.len(), 1);
    assert_eq!(
        enstow::stow::normalize_path(stale_actions[0].target()),
        enstow::stow::normalize_path(&target_deep)
    );
}

#[test]
fn test_default_no_subcommand_cli_honors_prune_flag_and_config() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let bin = env!("CARGO_BIN_EXE_enstow");
    match std::process::Command::new(bin).arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => return,
    }

    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let pkg_dir = source_dir.path().join("agy");
    let scripts_dir = pkg_dir
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("my-skill")
        .join("scripts");
    fs::create_dir_all(&scripts_dir).unwrap();

    let kept_file = pkg_dir
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("my-skill")
        .join("SKILL.md");
    let stale_file = scripts_dir.join("removed.sh");
    fs::write(&kept_file, "# kept\n").unwrap();
    fs::write(&stale_file, "#!/bin/sh\n").unwrap();

    // 1. Initial stow using default no-subcommand invocation
    let init_out = std::process::Command::new(bin)
        .env_remove("ENSTOW_PRUNE")
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_PACKAGES")
        .env_remove("ENSTOW_PROFILE")
        .arg("--source")
        .arg(source_dir.path())
        .arg("--target")
        .arg(target_dir.path())
        .arg("agy")
        .output()
        .expect("Failed to execute enstow");
    assert!(
        init_out.status.success(),
        "initial default apply failed: {}",
        String::from_utf8_lossy(&init_out.stderr)
    );

    let target_kept = target_dir
        .path()
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("my-skill")
        .join("SKILL.md");
    let target_stale = target_dir
        .path()
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("my-skill")
        .join("scripts")
        .join("removed.sh");
    assert!(is_symlink_to(&target_kept, &kept_file));
    assert!(is_symlink_to(&target_stale, &stale_file));

    // Delete depth-6 source file
    fs::remove_file(&stale_file).unwrap();

    // 2. Default no-subcommand with `--prune` removes depth-6 stale symlink
    let prune_out = std::process::Command::new(bin)
        .env_remove("ENSTOW_PRUNE")
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_PACKAGES")
        .env_remove("ENSTOW_PROFILE")
        .arg("--source")
        .arg(source_dir.path())
        .arg("--target")
        .arg(target_dir.path())
        .arg("--prune")
        .arg("agy")
        .output()
        .expect("Failed to execute enstow --prune");
    assert!(
        prune_out.status.success(),
        "default apply --prune failed: {}",
        String::from_utf8_lossy(&prune_out.stderr)
    );
    assert!(fs::symlink_metadata(&target_stale).is_err());
    assert!(is_symlink_to(&target_kept, &kept_file));

    // 3. Default no-subcommand with repo-local `.enstow.toml` setting `prune = true`
    fs::create_dir_all(target_stale.parent().unwrap()).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&stale_file, &target_stale).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&stale_file, &target_stale).unwrap();
    assert!(fs::symlink_metadata(&target_stale).is_ok());

    fs::write(
        source_dir.path().join(".enstow.toml"),
        "prune = true\npackages = [\"agy\"]\n",
    )
    .unwrap();

    let cfg_out = std::process::Command::new(bin)
        .env_remove("ENSTOW_PRUNE")
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_PACKAGES")
        .env_remove("ENSTOW_PROFILE")
        .arg("--source")
        .arg(source_dir.path())
        .arg("--target")
        .arg(target_dir.path())
        .output()
        .expect("Failed to execute default enstow with config prune = true");
    assert!(
        cfg_out.status.success(),
        "default apply with config prune failed: {}",
        String::from_utf8_lossy(&cfg_out.stderr)
    );
    assert!(fs::symlink_metadata(&target_stale).is_err());
    assert!(is_symlink_to(&target_kept, &kept_file));
}
