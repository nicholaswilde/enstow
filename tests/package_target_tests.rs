use age::secrecy::ExposeSecret;
use age::Recipient;
use enstow::cli::CommonArgs;
use enstow::config::{
    expand_tilde, resolve_common_args, resolve_package_targets, resolve_target_for_package,
    ConfigFile, ConfigFormat,
};
use enstow::diff::compute_diff;
use enstow::doctor::{run_doctor, CheckSeverity};
use enstow::hook::{
    run_post_apply_hooks, run_post_unstow_hooks, run_pre_apply_hooks, run_pre_unstow_hooks,
};
use enstow::stow::{
    add_file, check_status, deploy_edited_secret, execute_plan_interactive_with_target_roots,
    execute_unstow_plan_with_roots, is_symlink_to, normalize_path, plan_prune, plan_stow,
    plan_unstow, resolve_secret_target_with_package_targets, EntryStatus,
};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

fn write_encrypted_age(key_file: &Path, dest: &Path, plaintext: &[u8]) {
    let key = if key_file.exists() {
        let content = fs::read_to_string(key_file).unwrap();
        content.trim().parse::<age::x25519::Identity>().unwrap()
    } else {
        let generated = age::x25519::Identity::generate();
        fs::write(key_file, generated.to_string().expose_secret()).unwrap();
        generated
    };
    let pubkey = key.to_public();
    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted = Vec::new();
    let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(dest, encrypted).unwrap();
}

#[test]
fn test_parse_package_target_all_formats() {
    let toml_str = r#"
target = "/home/tester"
packages = ["zsh", "systemd"]

[package.systemd]
target = "~/.config/systemd/user"
"#;
    let toml_cfg = ConfigFile::parse(toml_str, ConfigFormat::Toml).unwrap();
    assert_eq!(
        toml_cfg.package.as_ref().unwrap()["systemd"].target,
        Some(PathBuf::from("~/.config/systemd/user"))
    );

    let yaml_str = r#"
target: /home/tester
packages:
  - zsh
  - systemd
package:
  systemd:
    target: ~/.config/systemd/user
"#;
    let yaml_cfg = ConfigFile::parse(yaml_str, ConfigFormat::Yaml).unwrap();
    assert_eq!(
        yaml_cfg.package.as_ref().unwrap()["systemd"].target,
        Some(PathBuf::from("~/.config/systemd/user"))
    );

    let json_str = r#"{
  "target": "/home/tester",
  "packages": ["zsh", "systemd"],
  "package": {
    "systemd": {
      "target": "~/.config/systemd/user"
    }
  }
}"#;
    let json_cfg = ConfigFile::parse(json_str, ConfigFormat::Json).unwrap();
    assert_eq!(
        json_cfg.package.as_ref().unwrap()["systemd"].target,
        Some(PathBuf::from("~/.config/systemd/user"))
    );
}

#[test]
fn test_package_target_expansion_relative_and_cli_precedence() {
    let ws = tempdir().unwrap();
    let global_target = ws.path().join("home");
    let abs_target = ws.path().join("external_systemd");
    fs::create_dir_all(&global_target).unwrap();

    let toml_str = format!(
        r#"
target = "{}"
packages = ["zsh", "systemd", "relpkg", "tilde_pkg", "empty_pkg"]

[package.systemd]
target = "{}"

[package.relpkg]
target = ".config/relpkg"

[package.tilde_pkg]
target = "~/.config/tilde_pkg"

[package.empty_pkg]
target = "   "
"#,
        global_target.to_string_lossy().replace('\\', "\\\\"),
        abs_target.to_string_lossy().replace('\\', "\\\\"),
    );
    let cfg = ConfigFile::parse(&toml_str, ConfigFormat::Toml).unwrap();

    // Without CLI -t override (assuming ENSTOW_TARGET unset in test env):
    let pkg_targets = resolve_package_targets(None, Some(&cfg), &global_target);
    assert_eq!(pkg_targets.get("systemd"), Some(&abs_target));
    assert_eq!(
        pkg_targets.get("relpkg"),
        Some(&global_target.join(".config").join("relpkg"))
    );
    assert_eq!(
        pkg_targets.get("tilde_pkg"),
        Some(&expand_tilde(Path::new("~/.config/tilde_pkg")))
    );
    assert!(!pkg_targets.contains_key("empty_pkg"));
    assert!(!pkg_targets.contains_key("zsh"));

    assert_eq!(
        resolve_target_for_package(None, Some(&cfg), "systemd"),
        abs_target
    );
    assert_eq!(
        resolve_target_for_package(None, Some(&cfg), "zsh"),
        global_target
    );

    // Explicit CLI -t overrides all per-package targets
    let cli_override = ws.path().join("cli_stage");
    let pkg_targets_cli = resolve_package_targets(Some(&cli_override), Some(&cfg), &cli_override);
    assert!(pkg_targets_cli.is_empty());
    assert_eq!(
        resolve_target_for_package(Some(&cli_override), Some(&cfg), "systemd"),
        cli_override
    );
}

#[test]
fn test_per_package_target_apply_status_diff_unstow_and_preserve_root() {
    let ws = tempdir().unwrap();
    let source = ws.path().join("dotfiles");
    let global_target = ws.path().join("home");
    let systemd_target = ws.path().join("custom_systemd_root");
    let nested_rel_target = global_target.join(".config").join("nested_app");

    fs::create_dir_all(source.join("zsh")).unwrap();
    fs::create_dir_all(source.join("systemd").join("sub")).unwrap();
    fs::create_dir_all(source.join("nested")).unwrap();
    fs::create_dir_all(&global_target).unwrap();
    fs::create_dir_all(&systemd_target).unwrap();

    let zshrc_src = source.join("zsh").join(".zshrc");
    let svc_src = source.join("systemd").join("my.service");
    let sub_svc_src = source.join("systemd").join("sub").join("timer.timer");
    let nested_src = source.join("nested").join("app.conf");
    fs::write(&zshrc_src, "export ZSH=1\n").unwrap();
    fs::write(&svc_src, "[Unit]\nDescription=Test\n").unwrap();
    fs::write(&sub_svc_src, "[Timer]\nOnBootSec=5min\n").unwrap();
    fs::write(&nested_src, "enabled = true\n").unwrap();

    let toml_str = format!(
        r#"
source = "{}"
target = "{}"
packages = ["zsh", "systemd", "nested"]

[package.systemd]
target = "{}"

[package.nested]
target = ".config/nested_app"
"#,
        source.to_string_lossy().replace('\\', "\\\\"),
        global_target.to_string_lossy().replace('\\', "\\\\"),
        systemd_target.to_string_lossy().replace('\\', "\\\\"),
    );
    let cfg = ConfigFile::parse(&toml_str, ConfigFormat::Toml).unwrap();
    let resolved = resolve_common_args(&CommonArgs::default(), Some(&cfg)).unwrap();
    let common = resolved.to_common_args();

    // 1. Plan & status before apply (all Missing)
    let actions = plan_stow(&common).unwrap();
    assert_eq!(actions.len(), 4);
    let statuses = check_status(&actions, None).unwrap();
    assert!(statuses.iter().all(|s| s.status == EntryStatus::Missing));

    // 2. Apply
    execute_plan_interactive_with_target_roots(
        &actions,
        false,
        None,
        &[],
        false,
        false,
        None,
        &common.active_target_roots(),
        Some(&resolved.permissions),
        false,
        false,
    )
    .unwrap();

    let zshrc_dst = global_target.join(".zshrc");
    let svc_dst = systemd_target.join("my.service");
    let sub_svc_dst = systemd_target.join("sub").join("timer.timer");
    let nested_dst = nested_rel_target.join("app.conf");

    assert!(is_symlink_to(&zshrc_dst, &zshrc_src));
    assert!(is_symlink_to(&svc_dst, &svc_src));
    assert!(is_symlink_to(&sub_svc_dst, &sub_svc_src));
    assert!(is_symlink_to(&nested_dst, &nested_src));

    // 3. Status after apply (all Synced)
    let statuses_after = check_status(&actions, None).unwrap();
    assert!(statuses_after
        .iter()
        .all(|s| s.status == EntryStatus::Synced));

    // 4. Diff after replacing custom target symlink with conflicting file
    fs::remove_file(&svc_dst).unwrap();
    fs::write(&svc_dst, "[Unit]\nDescription=Modified\n").unwrap();
    let diffs = compute_diff(&actions, None, false).unwrap();
    assert_eq!(diffs.len(), 1);
    assert!(diffs[0].diff.contains("Description=Modified"));
    assert!(diffs[0].diff.contains("Description=Test"));

    // Restore symlink for unstow verification
    fs::remove_file(&svc_dst).unwrap();
    execute_plan_interactive_with_target_roots(
        &actions,
        false,
        None,
        &[],
        false,
        false,
        None,
        &common.active_target_roots(),
        Some(&resolved.permissions),
        false,
        false,
    )
    .unwrap();

    // 5. Unstow: removes links and empty `sub/` inside custom target,
    //    but MUST preserve both `systemd_target` and `nested_rel_target` roots themselves.
    let unstow_actions = plan_unstow(&common).unwrap();
    execute_unstow_plan_with_roots(&unstow_actions, &common.active_target_roots(), false, false)
        .unwrap();

    assert!(fs::symlink_metadata(&zshrc_dst).is_err());
    assert!(fs::symlink_metadata(&svc_dst).is_err());
    assert!(fs::symlink_metadata(&sub_svc_dst).is_err());
    assert!(fs::symlink_metadata(&nested_dst).is_err());
    assert!(!systemd_target.join("sub").exists());
    assert!(
        systemd_target.is_dir(),
        "External package target root must not be removed during unstow"
    );
    assert!(
        nested_rel_target.is_dir(),
        "Nested package target root must not be removed during unstow"
    );
}

#[test]
fn test_per_package_target_prune_restow_and_doctor() {
    let ws = tempdir().unwrap();
    let source = ws.path().join("dotfiles");
    let global_target = ws.path().join("home");
    let systemd_target = ws.path().join("ext_systemd");
    let key_file = ws.path().join("age.key");

    fs::create_dir_all(source.join("systemd")).unwrap();
    fs::create_dir_all(source.join("zsh")).unwrap();
    fs::create_dir_all(&global_target).unwrap();
    fs::create_dir_all(&systemd_target).unwrap();

    let live_src = source.join("systemd").join("live.service");
    let stale_src = source.join("systemd").join("old.service");
    let secret_src = source.join("systemd").join("creds.env.age");
    let zshrc_src = source.join("zsh").join(".zshrc");

    fs::write(&live_src, "live\n").unwrap();
    fs::write(&stale_src, "old\n").unwrap();
    fs::write(&zshrc_src, "zsh\n").unwrap();
    write_encrypted_age(&key_file, &secret_src, b"API_KEY=secret\n");

    let toml_str = format!(
        r#"
source = "{}"
target = "{}"
age_key_file = "{}"
packages = ["zsh", "systemd"]

[package.systemd]
target = "{}"

[package.systemd.permissions]
"creds.env" = "0600"
"#,
        source.to_string_lossy().replace('\\', "\\\\"),
        global_target.to_string_lossy().replace('\\', "\\\\"),
        key_file.to_string_lossy().replace('\\', "\\\\"),
        systemd_target.to_string_lossy().replace('\\', "\\\\"),
    );
    let cfg = ConfigFile::parse(&toml_str, ConfigFormat::Toml).unwrap();
    let cli = CommonArgs {
        age_key_file: Some(key_file.clone()),
        ..Default::default()
    };
    let resolved = resolve_common_args(&cli, Some(&cfg)).unwrap();
    let common = resolved.to_common_args();

    // Initial apply
    let actions = plan_stow(&common).unwrap();
    execute_plan_interactive_with_target_roots(
        &actions,
        false,
        common.age_key_file.as_deref(),
        &[],
        false,
        false,
        None,
        &common.active_target_roots(),
        Some(&resolved.permissions),
        false,
        false,
    )
    .unwrap();

    // Healthy doctor check
    let healthy_report = run_doctor(&common, Some(&resolved.permissions)).unwrap();
    assert!(
        healthy_report.healthy,
        "Expected healthy doctor report, got checks: {:?}",
        healthy_report.checks
    );

    // Delete `old.service` from source so symlink in `systemd_target` becomes dangling & stale
    fs::remove_file(&stale_src).unwrap();

    // Doctor must detect the dangling symlink inside the external package target
    let unhealthy_report = run_doctor(&common, Some(&resolved.permissions)).unwrap();
    assert!(!unhealthy_report.healthy);
    assert!(
        unhealthy_report.checks.iter().any(|c| {
            c.category == "symlink_health"
                && c.severity == CheckSeverity::Error
                && c.message.contains("old.service")
        }),
        "Expected dangling symlink check for old.service in custom target, got: {:?}",
        unhealthy_report.checks
    );

    // plan_prune must find the stale symlink in `systemd_target`
    let stale_actions = plan_prune(&common).unwrap();
    assert_eq!(stale_actions.len(), 1);
    assert_eq!(
        normalize_path(stale_actions[0].target()),
        normalize_path(&systemd_target.join("old.service"))
    );

    // Restow/prune removes stale symlink and keeps live symlink
    execute_unstow_plan_with_roots(&stale_actions, &common.active_target_roots(), false, false)
        .unwrap();
    assert!(fs::symlink_metadata(systemd_target.join("old.service")).is_err());
    assert!(is_symlink_to(
        &systemd_target.join("live.service"),
        &live_src
    ));
    assert!(systemd_target.join("creds.env").is_file());
}

#[test]
fn test_doctor_detects_collision_between_global_and_custom_package_target() {
    let ws = tempdir().unwrap();
    let source = ws.path().join("dotfiles");
    let global_target = ws.path().join("home");

    fs::create_dir_all(
        source
            .join("global_pkg")
            .join(".config")
            .join("systemd")
            .join("user"),
    )
    .unwrap();
    fs::create_dir_all(source.join("flat_pkg")).unwrap();
    fs::create_dir_all(&global_target).unwrap();

    fs::write(
        source
            .join("global_pkg")
            .join(".config")
            .join("systemd")
            .join("user")
            .join("dup.service"),
        "from global\n",
    )
    .unwrap();
    fs::write(source.join("flat_pkg").join("dup.service"), "from flat\n").unwrap();

    let toml_str = format!(
        r#"
source = "{}"
target = "{}"
packages = ["global_pkg", "flat_pkg"]

[package.flat_pkg]
target = ".config/systemd/user"
"#,
        source.to_string_lossy().replace('\\', "\\\\"),
        global_target.to_string_lossy().replace('\\', "\\\\"),
    );
    let cfg = ConfigFile::parse(&toml_str, ConfigFormat::Toml).unwrap();
    let resolved = resolve_common_args(&CommonArgs::default(), Some(&cfg)).unwrap();
    let common = resolved.to_common_args();

    let report = run_doctor(&common, None).unwrap();
    assert!(!report.healthy);
    assert!(report.checks.iter().any(|c| {
        c.category == "package_collisions"
            && c.severity == CheckSeverity::Error
            && c.message.contains("dup.service")
    }));
}

#[test]
fn test_per_package_target_hooks_receive_package_target_env() {
    let ws = tempdir().unwrap();
    let source = ws.path().join("dotfiles");
    let global_target = ws.path().join("home");
    let systemd_target = ws.path().join("systemd_units");
    let log_file = ws.path().join("hook_env.log");

    fs::create_dir_all(source.join("systemd")).unwrap();
    fs::create_dir_all(source.join("zsh")).unwrap();
    fs::create_dir_all(&global_target).unwrap();
    fs::create_dir_all(&systemd_target).unwrap();

    let (cmd_global_pre, cmd_pkg_pre, cmd_pkg_post, cmd_pkg_pre_u, cmd_pkg_post_u) =
        if cfg!(windows) {
            (
                format!("echo global_pre:%ENSTOW_TARGET%>> {}", log_file.display()),
                format!(
                    "echo pkg_pre:%ENSTOW_PACKAGE%:%ENSTOW_TARGET%>> {}",
                    log_file.display()
                ),
                format!(
                    "echo pkg_post:%ENSTOW_PACKAGE%:%ENSTOW_TARGET%>> {}",
                    log_file.display()
                ),
                format!(
                    "echo pkg_pre_u:%ENSTOW_PACKAGE%:%ENSTOW_TARGET%>> {}",
                    log_file.display()
                ),
                format!(
                    "echo pkg_post_u:%ENSTOW_PACKAGE%:%ENSTOW_TARGET%>> {}",
                    log_file.display()
                ),
            )
        } else {
            (
                format!(
                    "echo \"global_pre:$ENSTOW_TARGET\" >> \"{}\"",
                    log_file.display()
                ),
                format!(
                    "echo \"pkg_pre:$ENSTOW_PACKAGE:$ENSTOW_TARGET\" >> \"{}\"",
                    log_file.display()
                ),
                format!(
                    "echo \"pkg_post:$ENSTOW_PACKAGE:$ENSTOW_TARGET\" >> \"{}\"",
                    log_file.display()
                ),
                format!(
                    "echo \"pkg_pre_u:$ENSTOW_PACKAGE:$ENSTOW_TARGET\" >> \"{}\"",
                    log_file.display()
                ),
                format!(
                    "echo \"pkg_post_u:$ENSTOW_PACKAGE:$ENSTOW_TARGET\" >> \"{}\"",
                    log_file.display()
                ),
            )
        };

    let toml_str = format!(
        r#"
source = "{}"
target = "{}"
packages = ["zsh", "systemd"]

[hooks]
pre_apply = '{}'

[package.zsh.hooks]
pre_apply = '{}'

[package.systemd]
target = "{}"

[package.systemd.hooks]
pre_apply = '{}'
post_apply = '{}'
pre_unstow = '{}'
post_unstow = '{}'
"#,
        source.to_string_lossy().replace('\\', "\\\\"),
        global_target.to_string_lossy().replace('\\', "\\\\"),
        cmd_global_pre,
        cmd_pkg_pre,
        systemd_target.to_string_lossy().replace('\\', "\\\\"),
        cmd_pkg_pre,
        cmd_pkg_post,
        cmd_pkg_pre_u,
        cmd_pkg_post_u,
    );
    let cfg = ConfigFile::parse(&toml_str, ConfigFormat::Toml).unwrap();
    let resolved = resolve_common_args(&CommonArgs::default(), Some(&cfg)).unwrap();

    run_pre_apply_hooks(&resolved).unwrap();
    run_post_apply_hooks(&resolved).unwrap();
    run_pre_unstow_hooks(&resolved).unwrap();
    run_post_unstow_hooks(&resolved).unwrap();

    let lines: Vec<String> = fs::read_to_string(&log_file)
        .unwrap()
        .lines()
        .map(|l| l.trim().to_string())
        .collect();
    assert_eq!(
        lines,
        vec![
            format!("global_pre:{}", global_target.display()),
            format!("pkg_pre:zsh:{}", global_target.display()),
            format!("pkg_pre:systemd:{}", systemd_target.display()),
            format!("pkg_post:systemd:{}", systemd_target.display()),
            format!("pkg_pre_u:systemd:{}", systemd_target.display()),
            format!("pkg_post_u:systemd:{}", systemd_target.display()),
        ]
    );
}

#[test]
fn test_per_package_target_add_and_edit_apply() {
    let ws = tempdir().unwrap();
    let source = ws.path().join("dotfiles");
    let global_target = ws.path().join("home");
    let systemd_target = ws.path().join("systemd_units");
    let key_file = ws.path().join("age.key");

    fs::create_dir_all(source.join("systemd")).unwrap();
    fs::create_dir_all(&global_target).unwrap();
    fs::create_dir_all(&systemd_target).unwrap();

    let toml_str = format!(
        r#"
source = "{}"
target = "{}"
packages = ["systemd"]

[package.systemd]
target = "{}"
"#,
        source.to_string_lossy().replace('\\', "\\\\"),
        global_target.to_string_lossy().replace('\\', "\\\\"),
        systemd_target.to_string_lossy().replace('\\', "\\\\"),
    );
    let cfg = ConfigFile::parse(&toml_str, ConfigFormat::Toml).unwrap();

    // 1. add resolves systemd target automatically
    let unit_file = systemd_target.join("backup.service");
    fs::write(&unit_file, "[Unit]\nDescription=Backup\n").unwrap();
    let resolved_target = resolve_target_for_package(None, Some(&cfg), "systemd");
    let (_tgt, added_src) = add_file(
        &unit_file,
        "systemd",
        false,
        &[],
        None,
        &source,
        &resolved_target,
        false,
        false,
    )
    .unwrap();
    assert_eq!(
        fs::canonicalize(&added_src).unwrap(),
        fs::canonicalize(source.join("systemd").join("backup.service")).unwrap()
    );
    assert!(is_symlink_to(&unit_file, &added_src));

    // 2. edit --apply target resolution honors per-package target
    let secret_src = source.join("systemd").join("env.conf.age");
    write_encrypted_age(&key_file, &secret_src, b"SECRET=v1\n");
    let pkg_targets = resolve_package_targets(None, Some(&cfg), &global_target);
    let (eff_root, secret_target) = resolve_secret_target_with_package_targets(
        &secret_src,
        &source,
        &global_target,
        &["systemd".to_string()],
        &pkg_targets,
    )
    .unwrap();
    assert_eq!(eff_root, systemd_target);
    assert_eq!(secret_target, systemd_target.join("env.conf"));

    deploy_edited_secret(&secret_src, &secret_target, &eff_root, b"SECRET=v2\n", None).unwrap();
    assert_eq!(fs::read(&secret_target).unwrap(), b"SECRET=v2\n");

    // 3. Explicit CLI target override takes precedence over package target
    let cli_target = ws.path().join("cli_target");
    let empty_pkg_targets: BTreeMap<String, PathBuf> = BTreeMap::new();
    let (cli_root, cli_secret_target) = resolve_secret_target_with_package_targets(
        &secret_src,
        &source,
        &cli_target,
        &["systemd".to_string()],
        &empty_pkg_targets,
    )
    .unwrap();
    assert_eq!(cli_root, cli_target);
    assert_eq!(cli_secret_target, cli_target.join("env.conf"));
}

#[test]
fn test_cli_per_package_target_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_enstow");
    match std::process::Command::new(bin).arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => return,
    }

    let ws = tempdir().unwrap();
    let repo = ws.path().join("dotfiles");
    let global_target = ws.path().join("home");
    let systemd_target = global_target.join(".config").join("systemd").join("user");
    fs::create_dir_all(repo.join("zsh")).unwrap();
    fs::create_dir_all(repo.join("systemd")).unwrap();
    fs::create_dir_all(&global_target).unwrap();

    fs::write(repo.join("zsh").join(".zshrc"), "export ZSH=1\n").unwrap();
    fs::write(
        repo.join("systemd").join("demo.service"),
        "[Unit]\nDescription=Demo\n",
    )
    .unwrap();
    fs::write(
        repo.join(".enstow.toml"),
        format!(
            r#"
source = "."
target = "{}"
packages = ["zsh", "systemd"]

[package.systemd]
target = ".config/systemd/user"
"#,
            global_target.to_string_lossy().replace('\\', "\\\\"),
        ),
    )
    .unwrap();

    // 1. Apply
    let apply = std::process::Command::new(bin)
        .current_dir(&repo)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_TARGET")
        .env_remove("ENSTOW_SOURCE")
        .arg("apply")
        .output()
        .unwrap();
    assert!(
        apply.status.success(),
        "apply failed: {}",
        String::from_utf8_lossy(&apply.stderr)
    );
    assert!(is_symlink_to(
        &global_target.join(".zshrc"),
        &repo.join("zsh").join(".zshrc")
    ));
    assert!(is_symlink_to(
        &systemd_target.join("demo.service"),
        &repo.join("systemd").join("demo.service")
    ));

    // 2. Status --check
    let status = std::process::Command::new(bin)
        .current_dir(&repo)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_TARGET")
        .env_remove("ENSTOW_SOURCE")
        .args(["status", "--check"])
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "status --check failed: stdout={} stderr={}",
        String::from_utf8_lossy(&status.stdout),
        String::from_utf8_lossy(&status.stderr)
    );

    // 3. Doctor
    let doctor = std::process::Command::new(bin)
        .current_dir(&repo)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_TARGET")
        .env_remove("ENSTOW_SOURCE")
        .arg("doctor")
        .output()
        .unwrap();
    assert!(
        doctor.status.success(),
        "doctor failed: stdout={} stderr={}",
        String::from_utf8_lossy(&doctor.stdout),
        String::from_utf8_lossy(&doctor.stderr)
    );

    // 4. Unstow
    let unstow = std::process::Command::new(bin)
        .current_dir(&repo)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_TARGET")
        .env_remove("ENSTOW_SOURCE")
        .arg("unstow")
        .output()
        .unwrap();
    assert!(
        unstow.status.success(),
        "unstow failed: {}",
        String::from_utf8_lossy(&unstow.stderr)
    );
    assert!(fs::symlink_metadata(global_target.join(".zshrc")).is_err());
    assert!(fs::symlink_metadata(systemd_target.join("demo.service")).is_err());
    assert!(systemd_target.is_dir());

    // 5. CLI add into custom-target package without passing -t
    let new_unit = systemd_target.join("extra.service");
    fs::write(&new_unit, "[Unit]\nDescription=Extra\n").unwrap();
    let add_out = std::process::Command::new(bin)
        .current_dir(&repo)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_TARGET")
        .env_remove("ENSTOW_SOURCE")
        .args(["add", new_unit.to_str().unwrap(), "-p", "systemd"])
        .output()
        .unwrap();
    assert!(
        add_out.status.success(),
        "add failed: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );
    assert!(is_symlink_to(
        &new_unit,
        &repo.join("systemd").join("extra.service")
    ));

    // 6. CLI -t overrides per-package target
    let cli_stage = ws.path().join("cli_stage");
    fs::create_dir_all(&cli_stage).unwrap();
    let apply_cli = std::process::Command::new(bin)
        .current_dir(&repo)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_TARGET")
        .env_remove("ENSTOW_SOURCE")
        .args(["apply", "-t", cli_stage.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        apply_cli.status.success(),
        "apply -t failed: {}",
        String::from_utf8_lossy(&apply_cli.stderr)
    );
    assert!(is_symlink_to(
        &cli_stage.join("demo.service"),
        &repo.join("systemd").join("demo.service")
    ));
    assert!(fs::symlink_metadata(systemd_target.join("demo.service")).is_err());
}
