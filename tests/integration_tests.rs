use age::secrecy::ExposeSecret;
use age::Recipient;
use enstow::cli::CommonArgs;
use enstow::stow::{execute_plan, plan_stow};
use std::fs;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_end_to_end_nested_stow_with_mixed_regular_and_age_files() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // 1. Setup nested regular dotfiles
    let bash_dir = source_dir.path().join(".config").join("bash");
    fs::create_dir_all(&bash_dir).unwrap();
    let bashrc = bash_dir.join("bashrc");
    fs::write(&bashrc, "export FOO=bar\n").unwrap();

    let root_file = source_dir.path().join(".profile");
    fs::write(&root_file, "# profile\n").unwrap();

    // 2. Setup age encrypted secret inside nested dir
    let auth_dir = source_dir.path().join(".config").join("gh");
    fs::create_dir_all(&auth_dir).unwrap();
    let hosts_age = auth_dir.join("hosts.yml.age");

    let key_dir = tempdir().unwrap();
    let key_file = key_dir.path().join("test_key.txt");
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    let plaintext_secret = b"github.com:\n  oauth_token: gho_secret123\n";
    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(plaintext_secret).unwrap();
    writer.finish().unwrap();
    fs::write(&hosts_age, encrypted_buf).unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: false,
        force: false,
        prune: false,
        age_key_file: Some(key_file.clone()),
        packages: Vec::new(),
        ignore: Vec::new(),
        ..Default::default()
    };

    // 3. Plan stow
    let plan = plan_stow(&args).unwrap();
    assert_eq!(plan.len(), 3); // bashrc, .profile, hosts.yml.age

    // 4. Dry run verification: ensure no target files exist
    execute_plan(&plan, true, Some(&key_file), false).unwrap();
    assert!(!target_dir
        .path()
        .join(".config")
        .join("bash")
        .join("bashrc")
        .exists());
    assert!(!target_dir.path().join(".profile").exists());
    assert!(!target_dir
        .path()
        .join(".config")
        .join("gh")
        .join("hosts.yml")
        .exists());

    // 5. Real execution
    execute_plan(&plan, false, Some(&key_file), false).unwrap();

    // 6. Verify regular symlinks
    let target_bashrc = target_dir
        .path()
        .join(".config")
        .join("bash")
        .join("bashrc");
    assert!(fs::symlink_metadata(&target_bashrc)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(enstow::stow::is_symlink_to(&target_bashrc, &bashrc));
    assert_eq!(
        fs::canonicalize(fs::read_link(&target_bashrc).unwrap()).unwrap(),
        fs::canonicalize(&bashrc).unwrap()
    );

    let target_profile = target_dir.path().join(".profile");
    assert!(fs::symlink_metadata(&target_profile)
        .unwrap()
        .file_type()
        .is_symlink());
    assert!(enstow::stow::is_symlink_to(&target_profile, &root_file));
    assert_eq!(
        fs::canonicalize(fs::read_link(&target_profile).unwrap()).unwrap(),
        fs::canonicalize(&root_file).unwrap()
    );

    // 7. Verify decrypted file and Unix permissions
    let target_hosts = target_dir
        .path()
        .join(".config")
        .join("gh")
        .join("hosts.yml");
    assert!(target_hosts.exists());
    assert!(!fs::symlink_metadata(&target_hosts)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&target_hosts).unwrap(), plaintext_secret);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&target_hosts).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn test_config_and_env_dry_run_and_force_end_to_end() {
    let orig_dry_run = std::env::var("ENSTOW_DRY_RUN").ok();
    let orig_force = std::env::var("ENSTOW_FORCE").ok();
    std::env::remove_var("ENSTOW_DRY_RUN");
    std::env::remove_var("ENSTOW_FORCE");

    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let dotfile = source_dir.path().join(".testrc");
    fs::write(&dotfile, "hello=world\n").unwrap();

    let target_file = target_dir.path().join(".testrc");

    // 1. Config file with dry_run = true
    let config_path = source_dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
dry_run = true
force = false
"#,
    )
    .unwrap();
    let config = enstow::config::ConfigFile::load_from_path(&config_path).unwrap();

    let cli_args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: false,
        force: false,
        prune: false,
        ..Default::default()
    };

    // Apply with config dry_run = true
    let common = enstow::config::resolve_common_args(&cli_args, Some(&config)).to_common_args();
    assert!(common.dry_run);
    assert!(!common.force);

    let plan = plan_stow(&common).unwrap();
    execute_plan(&plan, common.dry_run, None, common.force).unwrap();
    assert!(fs::symlink_metadata(&target_file).is_err());

    // 2. Env var ENSTOW_DRY_RUN=0 overrides config dry_run = true
    std::env::set_var("ENSTOW_DRY_RUN", "0");
    let common = enstow::config::resolve_common_args(&cli_args, Some(&config)).to_common_args();
    assert!(!common.dry_run);

    execute_plan(&plan, common.dry_run, None, common.force).unwrap();
    assert!(fs::symlink_metadata(&target_file).is_ok());
    assert!(enstow::stow::is_symlink_to(&target_file, &dotfile));

    // 3. Unstow with config dry_run = true (env removed)
    std::env::remove_var("ENSTOW_DRY_RUN");
    let common = enstow::config::resolve_common_args(&cli_args, Some(&config)).to_common_args();
    assert!(common.dry_run);

    let unstow_plan = enstow::stow::plan_unstow(&common).unwrap();
    enstow::stow::execute_unstow_plan(&unstow_plan, &common.target_path(), common.dry_run).unwrap();
    // Target symlink still present because of dry_run
    assert!(fs::symlink_metadata(&target_file).is_ok());

    // 4. Force resolution: create a conflicting regular file at target
    fs::remove_file(&target_file).unwrap();
    fs::write(&target_file, "conflict content\n").unwrap();

    // Without force, execute_plan fails on conflict
    let common_no_force = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: false,
        force: false,
        prune: false,
        ..Default::default()
    };
    let resolved_no_force =
        enstow::config::resolve_common_args(&common_no_force, Some(&config)).to_common_args();
    assert!(!resolved_no_force.force);
    assert!(execute_plan(&plan, false, None, resolved_no_force.force).is_err());

    // Overriding with ENSTOW_FORCE=1 allows overwriting
    std::env::set_var("ENSTOW_FORCE", "1");
    let resolved_force =
        enstow::config::resolve_common_args(&common_no_force, Some(&config)).to_common_args();
    assert!(resolved_force.force);
    execute_plan(&plan, false, None, resolved_force.force).unwrap();
    assert!(enstow::stow::is_symlink_to(&target_file, &dotfile));

    // Cleanup env
    std::env::remove_var("ENSTOW_DRY_RUN");
    std::env::remove_var("ENSTOW_FORCE");
    if let Some(v) = orig_dry_run {
        std::env::set_var("ENSTOW_DRY_RUN", v);
    }
    if let Some(v) = orig_force {
        std::env::set_var("ENSTOW_FORCE", v);
    }
}

#[test]
fn test_status_json_resolution_and_output_end_to_end() {
    let orig_json = std::env::var("ENSTOW_JSON").ok();
    std::env::remove_var("ENSTOW_JSON");

    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let config_dir = tempdir().unwrap();

    let dotfile = source_dir.path().join(".zshrc");
    fs::write(&dotfile, "export ZSH=1\n").unwrap();

    let config_path = config_dir.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
json = true
"#,
    )
    .unwrap();
    let config = enstow::config::ConfigFile::load_from_path(&config_path).unwrap();

    let cli_args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        ..Default::default()
    };

    let common = enstow::config::resolve_common_args(&cli_args, Some(&config)).to_common_args();
    let plan = plan_stow(&common).unwrap();
    let statuses = enstow::stow::check_status(&plan, None).unwrap();

    // 1. Config json = true resolves to json output enabled by default
    let json_enabled = enstow::config::resolve_json(false, Some(&config));
    assert!(json_enabled);

    // Verify JSON serialization format
    let json_output = serde_json::to_string_pretty(&statuses).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 1);
    assert_eq!(parsed[0]["status"], "missing");

    // 2. ENSTOW_JSON=0 overrides config json = true to false
    std::env::set_var("ENSTOW_JSON", "0");
    assert!(!enstow::config::resolve_json(false, Some(&config)));

    // 3. CLI --json flag overrides ENSTOW_JSON=0
    assert!(enstow::config::resolve_json(true, Some(&config)));

    // 4. ENSTOW_JSON=1 enables json without config or CLI flag
    std::env::set_var("ENSTOW_JSON", "1");
    assert!(enstow::config::resolve_json(false, None));

    // Cleanup env
    std::env::remove_var("ENSTOW_JSON");
    if let Some(v) = orig_json {
        std::env::set_var("ENSTOW_JSON", v);
    }
}
