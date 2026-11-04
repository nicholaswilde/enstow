use age::secrecy::ExposeSecret;
use age::Recipient;
use enstow::cli::CommonArgs;
use enstow::config::{
    resolve_common_args, ConfigFile, ConfigFormat, PermissionMode, PermissionsConfig,
};
use enstow::stow::{execute_plan_with_backup_and_permissions, plan_stow};
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;

#[test]
fn test_parse_permission_modes() {
    assert_eq!(PermissionMode::Str("0755".into()).to_mode().unwrap(), 0o755);
    assert_eq!(PermissionMode::Str("755".into()).to_mode().unwrap(), 0o755);
    assert_eq!(
        PermissionMode::Str("0o755".into()).to_mode().unwrap(),
        0o755
    );
    assert_eq!(PermissionMode::Str("0644".into()).to_mode().unwrap(), 0o644);
    assert_eq!(PermissionMode::Str("0600".into()).to_mode().unwrap(), 0o600);
    assert_eq!(PermissionMode::Str("0400".into()).to_mode().unwrap(), 0o400);
    assert_eq!(PermissionMode::Str("0".into()).to_mode().unwrap(), 0);

    assert_eq!(PermissionMode::Int(0o755).to_mode().unwrap(), 0o755);
    assert_eq!(PermissionMode::Int(755).to_mode().unwrap(), 0o755);
    assert_eq!(PermissionMode::Int(644).to_mode().unwrap(), 0o644);
    assert_eq!(PermissionMode::Int(600).to_mode().unwrap(), 0o600);

    assert!(PermissionMode::Str("999".into()).to_mode().is_err());
    assert!(PermissionMode::Str("invalid".into()).to_mode().is_err());
    assert!(PermissionMode::Int(0o10000).to_mode().is_err());
}

#[test]
fn test_config_deserialize_permissions_all_formats() {
    let toml_str = r#"
[permissions]
"**/*.sh" = "0755"
"**/*.key" = "0400"

[package.ssh.permissions]
"id_ed25519" = "0600"
"#;
    let cfg_toml = ConfigFile::parse(toml_str, ConfigFormat::Toml).unwrap();
    let perms = cfg_toml.permissions.as_ref().unwrap();
    assert_eq!(
        perms.get("**/*.sh"),
        Some(&PermissionMode::Str("0755".into()))
    );
    assert_eq!(
        perms.get("**/*.key"),
        Some(&PermissionMode::Str("0400".into()))
    );
    let pkg_cfg = cfg_toml.package.as_ref().unwrap();
    assert_eq!(
        pkg_cfg.get("ssh").unwrap().permissions.get("id_ed25519"),
        Some(&PermissionMode::Str("0600".into()))
    );

    let yaml_str = r#"
permissions:
  "**/*.sh": "0755"
package_permissions:
  ssh:
    "id_ed25519": "0600"
"#;
    let cfg_yaml = ConfigFile::parse(yaml_str, ConfigFormat::Yaml).unwrap();
    assert!(cfg_yaml.permissions.is_some());
    assert!(cfg_yaml.package_permissions.is_some());

    let json_str = r#"
{
  "permissions": {
    "**/*.sh": "0755"
  },
  "package_permissions": {
    "ssh": {
      "id_ed25519": "0600"
    }
  }
}
"#;
    let cfg_json = ConfigFile::parse(json_str, ConfigFormat::Json).unwrap();
    assert!(cfg_json.permissions.is_some());
    assert!(cfg_json.package_permissions.is_some());
}

#[test]
fn test_permissions_resolve_mode_matching() {
    let mut config = PermissionsConfig::default();
    config.add_rule("**/*.sh".into(), 0o755, None);
    config.add_rule("*.env".into(), 0o640, None);
    config.add_rule("id_ed25519".into(), 0o600, Some("ssh".into()));

    let target_root = Path::new("/home/user");

    // Match **/*.sh
    let script_path = Path::new("/home/user/.local/bin/deploy.sh");
    assert_eq!(
        config.resolve_mode(script_path, None, Some(target_root)),
        0o755
    );

    // Match *.env
    let env_path = Path::new("/home/user/app.env");
    assert_eq!(
        config.resolve_mode(env_path, None, Some(target_root)),
        0o640
    );

    // Match package-specific ssh key
    let key_path = Path::new("/home/user/.ssh/id_ed25519");
    let ssh_source = Path::new("/dotfiles/ssh/.ssh/id_ed25519.age");
    assert_eq!(
        config.resolve_mode(key_path, Some(ssh_source), Some(target_root)),
        0o600
    );

    // Same key name but different package should not match package-specific rule
    let other_source = Path::new("/dotfiles/other/.ssh/id_ed25519.age");
    assert_eq!(
        config.resolve_mode(key_path, Some(other_source), Some(target_root)),
        0o600 // falls back to default 0600
    );

    // Unmatched file defaults to 0600
    let secret_file = Path::new("/home/user/secrets.txt");
    assert_eq!(
        config.resolve_mode(secret_file, None, Some(target_root)),
        0o600
    );
}

#[test]
fn test_write_secure_file_with_custom_mode() {
    let dir = tempdir().unwrap();
    let secret_dest = dir.path().join("script.sh");
    let content = b"#!/bin/sh\necho hello\n";

    enstow::crypto::write_secure_file_with_mode(&secret_dest, content, false, 0o755).unwrap();
    assert_eq!(fs::read(&secret_dest).unwrap(), content);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(&secret_dest).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o755);
    }
}

#[test]
fn test_end_to_end_custom_permissions_deployment() {
    let temp = tempdir().unwrap();
    let source_dir = temp.path().join("dotfiles");
    let target_dir = temp.path().join("home");
    let key_file = temp.path().join("age-key.txt");

    fs::create_dir_all(&source_dir).unwrap();
    fs::create_dir_all(&target_dir).unwrap();

    let pkg_dir = source_dir.join("utils");
    fs::create_dir_all(&pkg_dir).unwrap();

    // Generate age key
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    let recipient: &dyn Recipient = &pubkey;

    // Encrypt script file
    let script_path = pkg_dir.join("run.sh.age");
    let script_content = b"#!/bin/bash\necho test\n";
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(script_content).unwrap();
    writer.finish().unwrap();
    fs::write(&script_path, encrypted_buf).unwrap();

    // Encrypt env file
    let env_path = pkg_dir.join("secret.env.age");
    let env_content = b"API_KEY=secret123\n";
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(env_content).unwrap();
    writer.finish().unwrap();
    fs::write(&env_path, encrypted_buf).unwrap();

    // Config with custom permission for *.sh
    let toml_content = r#"
[permissions]
"**/*.sh" = "0755"
"#;
    let cfg = ConfigFile::parse(toml_content, ConfigFormat::Toml).unwrap();

    let cli_args = CommonArgs {
        source: Some(source_dir.clone()),
        target: Some(target_dir.clone()),
        packages: vec!["utils".to_string()],
        dry_run: false,
        force: false,
        prune: false,
        age_key_file: Some(key_file.clone()),
        profile: None,
        ignore: Vec::new(),
        backup: false,
        backup_dir: None,
        ..Default::default()
    };

    let resolved = resolve_common_args(&cli_args, Some(&cfg)).unwrap();
    let common = resolved.to_common_args();

    let actions = plan_stow(&common).unwrap();
    assert_eq!(actions.len(), 2);

    execute_plan_with_backup_and_permissions(
        &actions,
        common.dry_run,
        common.age_key_file.as_deref(),
        common.force,
        common.backup,
        Some(&common.backup_dir_path()),
        Some(&common.target_path()),
        Some(&resolved.permissions),
        common.adopt,
    )
    .unwrap();

    let target_script = target_dir.join("run.sh");
    let target_env = target_dir.join("secret.env");

    assert_eq!(fs::read(&target_script).unwrap(), script_content);
    assert_eq!(fs::read(&target_env).unwrap(), env_content);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let script_meta = fs::metadata(&target_script).unwrap();
        assert_eq!(script_meta.permissions().mode() & 0o777, 0o755);

        let env_meta = fs::metadata(&target_env).unwrap();
        assert_eq!(env_meta.permissions().mode() & 0o777, 0o600);
    }
}
