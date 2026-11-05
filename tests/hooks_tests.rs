use enstow::cli::{Cli, CommonArgs};
use enstow::config::{resolve_common_args, ConfigFile, ConfigFormat};
use enstow::hook::{run_post_apply_hooks, run_pre_apply_hooks};
use enstow::stow::{execute_plan_with_backup_and_permissions, plan_stow};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_config_deserialize_hooks_all_formats() {
    let toml_str = r#"
[hooks]
pre_apply = "echo global pre"
post_apply = ["echo global post 1", "echo global post 2"]

[package.bat.hooks]
post_apply = "bat cache --build"
pre_unstow = "echo unstow bat"
"#;
    let cfg_toml = ConfigFile::parse(toml_str, ConfigFormat::Toml).unwrap();
    let hooks = cfg_toml.hooks.as_ref().unwrap();
    assert_eq!(hooks.pre_apply, vec!["echo global pre"]);
    assert_eq!(
        hooks.post_apply,
        vec!["echo global post 1", "echo global post 2"]
    );

    let pkg_cfg = cfg_toml.package.as_ref().unwrap();
    let bat_hooks = pkg_cfg.get("bat").unwrap().hooks.as_ref().unwrap();
    assert_eq!(bat_hooks.post_apply, vec!["bat cache --build"]);
    assert_eq!(bat_hooks.pre_unstow, vec!["echo unstow bat"]);

    // Test aliases (pre_stow, post_stow)
    let toml_alias = r#"
[hooks]
pre_stow = "echo alias pre"
post_stow = "echo alias post"
"#;
    let cfg_alias = ConfigFile::parse(toml_alias, ConfigFormat::Toml).unwrap();
    let alias_hooks = cfg_alias.hooks.as_ref().unwrap();
    assert_eq!(alias_hooks.pre_apply, vec!["echo alias pre"]);
    assert_eq!(alias_hooks.post_apply, vec!["echo alias post"]);

    // YAML format
    let yaml_str = r#"
hooks:
  pre_apply: "echo yaml pre"
  post_apply:
    - "echo yaml post 1"
    - "echo yaml post 2"
package:
  zsh:
    hooks:
      post_apply: "echo zsh post"
"#;
    let cfg_yaml = ConfigFile::parse(yaml_str, ConfigFormat::Yaml).unwrap();
    let y_hooks = cfg_yaml.hooks.as_ref().unwrap();
    assert_eq!(y_hooks.pre_apply, vec!["echo yaml pre"]);
    assert_eq!(
        y_hooks.post_apply,
        vec!["echo yaml post 1", "echo yaml post 2"]
    );
    let y_pkg = cfg_yaml.package.as_ref().unwrap();
    assert_eq!(
        y_pkg.get("zsh").unwrap().hooks.as_ref().unwrap().post_apply,
        vec!["echo zsh post"]
    );

    // JSON format
    let json_str = r#"{
        "hooks": {
            "pre_apply": "echo json pre",
            "post_apply": ["echo json post"]
        }
    }"#;
    let cfg_json = ConfigFile::parse(json_str, ConfigFormat::Json).unwrap();
    let j_hooks = cfg_json.hooks.as_ref().unwrap();
    assert_eq!(j_hooks.pre_apply, vec!["echo json pre"]);
    assert_eq!(j_hooks.post_apply, vec!["echo json post"]);
}

#[test]
fn test_cli_parsing_no_hooks_flag() {
    use clap::Parser;

    let args = Cli::parse_from(["enstow", "--no-hooks", "apply"]);
    assert!(args.common.no_hooks);

    let args_alias = Cli::parse_from(["enstow", "--skip-hooks", "apply"]);
    assert!(args_alias.common.no_hooks);

    let args_sub = Cli::parse_from(["enstow", "apply", "--no-hooks"]);
    if let Some(enstow::cli::Commands::Apply(common)) = args_sub.command {
        assert!(common.no_hooks);
    } else {
        panic!("Expected Apply subcommand");
    }
}

#[test]
fn test_hooks_pre_and_post_apply_execution_order_and_env() {
    let src = tempdir().unwrap();
    let tgt = tempdir().unwrap();
    let log_file = tgt.path().join("hook_log.txt");

    // Package "app"
    let app_src = src.path().join("app");
    fs::create_dir_all(&app_src).unwrap();
    fs::write(app_src.join("config.ini"), "setting=true\n").unwrap();

    let pre_cmd = format!(
        "echo pre:$ENSTOW_PACKAGE:$ENSTOW_HOOK_TYPE >> {}",
        log_file.display()
    );
    let post_cmd = format!(
        "echo post:$ENSTOW_PACKAGE:$ENSTOW_HOOK_TYPE >> {}",
        log_file.display()
    );

    let toml_str = format!(
        r#"
[package.app.hooks]
pre_apply = "{}"
post_apply = "{}"
"#,
        pre_cmd, post_cmd
    );
    let cfg = ConfigFile::parse(&toml_str, ConfigFormat::Toml).unwrap();

    let common = CommonArgs {
        source: Some(src.path().to_path_buf()),
        target: Some(tgt.path().to_path_buf()),
        packages: vec!["app".to_string()],
        ..Default::default()
    };

    let resolved = resolve_common_args(&common, Some(&cfg)).unwrap();
    let common_args = resolved.to_common_args();

    // 1. Run pre-apply hooks
    run_pre_apply_hooks(&resolved).unwrap();

    // File in target should not exist yet
    assert!(!tgt.path().join("config.ini").exists());

    // 2. Perform file stow actions
    let actions = plan_stow(&common_args).unwrap();
    execute_plan_with_backup_and_permissions(
        &actions,
        common_args.dry_run,
        None,
        common_args.force,
        common_args.backup,
        Some(&common_args.backup_dir_path()),
        Some(&common_args.target_path()),
        Some(&resolved.permissions),
        common_args.adopt,
    )
    .unwrap();

    // File in target exists now
    assert!(tgt.path().join("config.ini").exists());

    // 3. Run post-apply hooks
    run_post_apply_hooks(&resolved).unwrap();

    let log_contents = fs::read_to_string(&log_file).unwrap();
    let lines: Vec<&str> = log_contents.lines().collect();
    assert_eq!(lines, vec!["pre:app:pre_apply", "post:app:post_apply"]);
}

#[test]
fn test_pre_apply_hook_failure_halts_deployment_unless_force() {
    let src = tempdir().unwrap();
    let tgt = tempdir().unwrap();

    let app_src = src.path().join("app");
    fs::create_dir_all(&app_src).unwrap();
    fs::write(app_src.join("data.txt"), "hello").unwrap();

    let toml_str = r#"
[package.app.hooks]
pre_apply = "exit 1"
"#;
    let cfg = ConfigFile::parse(toml_str, ConfigFormat::Toml).unwrap();

    let common = CommonArgs {
        source: Some(src.path().to_path_buf()),
        target: Some(tgt.path().to_path_buf()),
        packages: vec!["app".to_string()],
        force: false,
        ..Default::default()
    };

    let resolved = resolve_common_args(&common, Some(&cfg)).unwrap();
    let result = run_pre_apply_hooks(&resolved);
    assert!(result.is_err(), "Expected failure without --force");

    // With force=true, pre-apply failure does not halt
    let common_force = CommonArgs {
        source: Some(src.path().to_path_buf()),
        target: Some(tgt.path().to_path_buf()),
        packages: vec!["app".to_string()],
        force: true,
        ..Default::default()
    };
    let resolved_force = resolve_common_args(&common_force, Some(&cfg)).unwrap();
    let result_force = run_pre_apply_hooks(&resolved_force);
    assert!(result_force.is_ok(), "Expected success with --force");
}

#[test]
fn test_dry_run_previews_hooks_without_executing() {
    let src = tempdir().unwrap();
    let tgt = tempdir().unwrap();
    let marker = tgt.path().join("marker.txt");

    let app_src = src.path().join("app");
    fs::create_dir_all(&app_src).unwrap();
    fs::write(app_src.join("file.txt"), "hello").unwrap();

    let toml_str = format!(
        r#"
[package.app.hooks]
pre_apply = "touch {}"
"#,
        marker.display()
    );
    let cfg = ConfigFile::parse(&toml_str, ConfigFormat::Toml).unwrap();

    let common = CommonArgs {
        source: Some(src.path().to_path_buf()),
        target: Some(tgt.path().to_path_buf()),
        packages: vec!["app".to_string()],
        dry_run: true,
        ..Default::default()
    };

    let resolved = resolve_common_args(&common, Some(&cfg)).unwrap();
    run_pre_apply_hooks(&resolved).unwrap();

    // Marker file should NOT be created
    assert!(!marker.exists());
}

#[test]
fn test_no_hooks_bypasses_execution() {
    let src = tempdir().unwrap();
    let tgt = tempdir().unwrap();
    let marker = tgt.path().join("marker.txt");

    let app_src = src.path().join("app");
    fs::create_dir_all(&app_src).unwrap();
    fs::write(app_src.join("file.txt"), "hello").unwrap();

    let toml_str = format!(
        r#"
[package.app.hooks]
pre_apply = "touch {}"
"#,
        marker.display()
    );
    let cfg = ConfigFile::parse(&toml_str, ConfigFormat::Toml).unwrap();

    let common = CommonArgs {
        source: Some(src.path().to_path_buf()),
        target: Some(tgt.path().to_path_buf()),
        packages: vec!["app".to_string()],
        no_hooks: true,
        ..Default::default()
    };

    let resolved = resolve_common_args(&common, Some(&cfg)).unwrap();
    run_pre_apply_hooks(&resolved).unwrap();

    assert!(!marker.exists());
}

#[test]
fn test_hooks_cli_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_enstow");

    match std::process::Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => {
            eprintln!("Skipping end-to-end binary test: target binary cannot be executed");
            return;
        }
    }

    let src = tempdir().unwrap();
    let tgt = tempdir().unwrap();
    let config_dir = tempdir().unwrap();
    let log_file = tgt.path().join("cli_hook_log.txt");

    let app_src = src.path().join("mypkg");
    fs::create_dir_all(&app_src).unwrap();
    fs::write(app_src.join("test.txt"), "content").unwrap();

    let pre_cmd = format!("echo pre >> {}", log_file.display());
    let post_cmd = format!("echo post >> {}", log_file.display());

    let config_path = config_dir.path().join("config.toml");
    let config_content = format!(
        r#"
[package.mypkg.hooks]
pre_apply = "{}"
post_apply = "{}"
"#,
        pre_cmd, post_cmd
    );
    fs::write(&config_path, config_content).unwrap();

    // 1. Dry run
    let dry_run_output = std::process::Command::new(bin)
        .arg("-C")
        .arg(&config_path)
        .arg("apply")
        .arg("-s")
        .arg(src.path())
        .arg("-t")
        .arg(tgt.path())
        .arg("-n")
        .arg("mypkg")
        .output()
        .unwrap();

    assert!(dry_run_output.status.success());
    let stdout = String::from_utf8_lossy(&dry_run_output.stdout);
    assert!(stdout.contains("[dry-run] HOOK"));
    assert!(!log_file.exists());

    // 2. Normal apply
    let apply_output = std::process::Command::new(bin)
        .arg("-C")
        .arg(&config_path)
        .arg("apply")
        .arg("-s")
        .arg(src.path())
        .arg("-t")
        .arg(tgt.path())
        .arg("mypkg")
        .output()
        .unwrap();

    assert!(apply_output.status.success());
    let log = fs::read_to_string(&log_file).unwrap();
    assert_eq!(log.trim().lines().collect::<Vec<_>>(), vec!["pre", "post"]);

    // 3. Failure without force
    let fail_config_path = config_dir.path().join("fail_config.toml");
    fs::write(
        &fail_config_path,
        r#"
[package.mypkg.hooks]
pre_apply = "exit 1"
"#,
    )
    .unwrap();

    let fail_output = std::process::Command::new(bin)
        .arg("-C")
        .arg(&fail_config_path)
        .arg("apply")
        .arg("-s")
        .arg(src.path())
        .arg("-t")
        .arg(tgt.path())
        .arg("mypkg")
        .output()
        .unwrap();

    assert!(!fail_output.status.success(), "Expected command failure exit code");

    // 4. Failure with force
    let force_output = std::process::Command::new(bin)
        .arg("-C")
        .arg(&fail_config_path)
        .arg("apply")
        .arg("-s")
        .arg(src.path())
        .arg("-t")
        .arg(tgt.path())
        .arg("--force")
        .arg("mypkg")
        .output()
        .unwrap();

    assert!(force_output.status.success(), "Expected success with --force");

    // 5. Bypass with --no-hooks
    let marker_no_hooks = tgt.path().join("never_created.txt");
    let no_hooks_config = config_dir.path().join("no_hooks_config.toml");
    fs::write(
        &no_hooks_config,
        format!(
            r#"
[package.mypkg.hooks]
pre_apply = "touch {}"
"#,
            marker_no_hooks.display()
        ),
    )
    .unwrap();

    let no_hooks_output = std::process::Command::new(bin)
        .arg("-C")
        .arg(&no_hooks_config)
        .arg("apply")
        .arg("-s")
        .arg(src.path())
        .arg("-t")
        .arg(tgt.path())
        .arg("--no-hooks")
        .arg("mypkg")
        .output()
        .unwrap();

    assert!(no_hooks_output.status.success());
    assert!(!marker_no_hooks.exists());
}
