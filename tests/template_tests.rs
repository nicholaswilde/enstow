use age::secrecy::ExposeSecret;
use age::Recipient;
use enstow::cli::CommonArgs;
use enstow::config::{resolve_common_args, ConfigFile, ConfigFormat, HostInfo};
use enstow::crypto::{
    detect_secret_type, render_template, target_plaintext_name, SecretType, TemplateContext,
};
use enstow::diff::compute_diff;
use enstow::stow::{
    check_status, execute_plan_with_backup_and_permissions, execute_unstow_plan, plan_stow,
    plan_unstow, EntryStatus,
};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_detect_tmpl_and_target_name() {
    use std::path::Path;
    assert_eq!(
        detect_secret_type(Path::new(".gitconfig.tmpl")),
        Some(SecretType::Template)
    );
    assert_eq!(
        target_plaintext_name(Path::new(".gitconfig.tmpl")),
        Some(".gitconfig".to_string())
    );
    assert_eq!(
        target_plaintext_name(Path::new("/dotfiles/git/.npmrc.tmpl")),
        Some(".npmrc".to_string())
    );
}

#[test]
fn test_render_template_variables_and_errors() {
    let mut env = BTreeMap::new();
    env.insert("USER".to_string(), "alice".to_string());

    let mut secrets = BTreeMap::new();
    secrets.insert("API_TOKEN".to_string(), "tok_12345".to_string());
    secrets.insert("github.token".to_string(), "ghp_abc".to_string());

    let ctx = TemplateContext {
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        hostname: "workstation".to_string(),
        profile: "work".to_string(),
        env,
        secrets,
    };

    let tmpl = "user={{ env.USER }}\nhost={{ hostname }} ({{ os }}/{{ arch }})\nprofile={{ profile }}\ntoken={{ secrets.API_TOKEN }}\ngh={{ secrets.github.token }}\n";
    let rendered = render_template(tmpl, &ctx).unwrap();
    assert_eq!(
        rendered,
        "user=alice\nhost=workstation (linux/x86_64)\nprofile=work\ntoken=tok_12345\ngh=ghp_abc\n"
    );

    // Missing secret error
    assert!(render_template("{{ secrets.MISSING }}", &ctx).is_err());
    // Missing env error
    assert!(render_template("{{ env.MISSING_VAR }}", &ctx).is_err());
    // Unknown variable error
    assert!(render_template("{{ unknown_var }}", &ctx).is_err());
    // Unclosed '{{' error
    assert!(render_template("hello {{ os", &ctx).is_err());
}

#[test]
fn test_end_to_end_template_rendering_with_age_secret_stores() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let key_file = key_dir.path().join("key.txt");
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    let encrypt_bytes = |data: &[u8]| -> Vec<u8> {
        let recipient: &dyn Recipient = &pubkey;
        let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
        let mut buf = Vec::new();
        let mut writer = encryptor.wrap_output(&mut buf).unwrap();
        writer.write_all(data).unwrap();
        writer.finish().unwrap();
        buf
    };

    let pkg_dir = source_dir.path().join("git");
    fs::create_dir_all(&pkg_dir).unwrap();

    // 1. Create hidden age key-value store `.secrets.toml.age` inside package
    //    (should NOT be deployed as a file to target, only used for template secrets)
    let toml_secrets = b"GPG_KEY = \"ABCD1234\"\n\n[github]\ntoken = \"ghp_secret999\"\n";
    fs::write(
        pkg_dir.join(".secrets.toml.age"),
        encrypt_bytes(toml_secrets),
    )
    .unwrap();

    // 2. Create `.secrets.env.age` at source root with additional key-value pair
    let env_secrets = b"# Comment\nexport NPM_TOKEN=\"npm_xyz_789\"\n";
    fs::write(
        source_dir.path().join(".secrets.env.age"),
        encrypt_bytes(env_secrets),
    )
    .unwrap();

    // 3. Create `.gitconfig.tmpl` in package
    let tmpl_content = r#"[user]
    signingkey = {{ secrets.GPG_KEY }}
[github]
    token = {{ secrets.github.token }}
[npm]
    token = {{ secrets.NPM_TOKEN }}
[host]
    os = {{ os }}
    arch = {{ arch }}
    hostname = {{ hostname }}
    profile = {{ profile }}
"#;
    fs::write(pkg_dir.join(".gitconfig.tmpl"), tmpl_content).unwrap();

    let config_toml = r#"
default_profile = "work"

[profiles.work]
packages = ["git"]

[permissions]
".gitconfig" = "0600"
"#;
    let mut cfg = ConfigFile::parse(config_toml, ConfigFormat::Toml).unwrap();
    cfg.source = Some(source_dir.path().to_path_buf());
    cfg.target = Some(target_dir.path().to_path_buf());
    cfg.age_key_file = Some(key_file.clone());

    let cli_args = CommonArgs {
        age_key_file: Some(key_file.clone()),
        ..Default::default()
    };
    let resolved = resolve_common_args(&cli_args, Some(&cfg)).unwrap();
    let common = resolved.to_common_args();

    // Plan stow: should only contain `.gitconfig.tmpl` -> `.gitconfig`
    // (`.secrets.toml.age` is automatically ignored by DEFAULT_IGNORES)
    let actions = plan_stow(&common).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].target(), target_dir.path().join(".gitconfig"));

    // Apply
    execute_plan_with_backup_and_permissions(
        &actions,
        false,
        Some(&key_file),
        false,
        false,
        None,
        Some(target_dir.path()),
        Some(&resolved.permissions),
        false,
    )
    .unwrap();

    let target_gitconfig = target_dir.path().join(".gitconfig");
    assert!(target_gitconfig.exists());

    let host = HostInfo::current();
    let expected = format!(
        "[user]\n    signingkey = ABCD1234\n[github]\n    token = ghp_secret999\n[npm]\n    token = npm_xyz_789\n[host]\n    os = {}\n    arch = {}\n    hostname = {}\n    profile = work\n",
        host.os, host.arch, host.hostname
    );
    assert_eq!(fs::read_to_string(&target_gitconfig).unwrap(), expected);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(&target_gitconfig).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    // Status should report Synced
    let statuses = check_status(&actions, Some(&key_file)).unwrap();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].status, EntryStatus::Synced);

    // Diff should be empty when in sync, and non-empty when target drifts
    let diffs_synced = compute_diff(&actions, Some(&key_file), false).unwrap();
    assert!(diffs_synced.is_empty());

    fs::write(&target_gitconfig, "drifted content\n").unwrap();
    let statuses_drifted = check_status(&actions, Some(&key_file)).unwrap();
    assert_eq!(statuses_drifted[0].status, EntryStatus::Modified);

    let diffs_drifted = compute_diff(&actions, Some(&key_file), true).unwrap();
    assert_eq!(diffs_drifted.len(), 1);
    assert!(diffs_drifted[0].diff.contains("[MASKED]"));

    // Unstow removes rendered target file
    let unstow_actions = plan_unstow(&common).unwrap();
    execute_unstow_plan(&unstow_actions, target_dir.path(), false).unwrap();
    assert!(fs::symlink_metadata(&target_gitconfig).is_err());

    // Doctor verifies template renderability
    let report = enstow::doctor::run_doctor(&common, Some(&resolved.permissions)).unwrap();
    assert!(report.healthy, "{:?}", report.checks);
    assert!(report
        .checks
        .iter()
        .any(|c| c.message.contains("Template renderable")));
}

#[test]
fn test_template_with_json_and_yaml_secret_stores() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let key_file = key_dir.path().join("key.txt");
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    let encrypt_bytes = |data: &[u8]| -> Vec<u8> {
        let recipient: &dyn Recipient = &pubkey;
        let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
        let mut buf = Vec::new();
        let mut writer = encryptor.wrap_output(&mut buf).unwrap();
        writer.write_all(data).unwrap();
        writer.finish().unwrap();
        buf
    };

    let pkg_dir = source_dir.path().join("app");
    fs::create_dir_all(&pkg_dir).unwrap();

    fs::write(
        pkg_dir.join(".secrets.json.age"),
        encrypt_bytes(br#"{"db":{"port":5432,"tls":true}}"#),
    )
    .unwrap();
    fs::write(
        pkg_dir.join(".secrets.auth.yaml.age"),
        encrypt_bytes(b"api_key: yaml_secret_key\n"),
    )
    .unwrap();
    fs::write(
        pkg_dir.join("app.conf.tmpl"),
        "port={{ secrets.db.port }}\ntls={{ secrets.db.tls }}\nkey={{ secrets.auth.api_key }}\n",
    )
    .unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_file.clone()),
        packages: vec!["app".to_string()],
        ..Default::default()
    };

    let actions = plan_stow(&args).unwrap();
    assert_eq!(actions.len(), 1);
    execute_plan_with_backup_and_permissions(
        &actions,
        false,
        Some(&key_file),
        false,
        false,
        None,
        Some(target_dir.path()),
        None,
        false,
    )
    .unwrap();

    assert_eq!(
        fs::read_to_string(target_dir.path().join("app.conf")).unwrap(),
        "port=5432\ntls=true\nkey=yaml_secret_key\n"
    );
}
