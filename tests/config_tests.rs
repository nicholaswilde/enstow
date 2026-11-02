use clap::Parser;
use enstow::cli::{Cli, Commands, CommonArgs};
use enstow::config::{
    load_config, parse_bool_env, resolve_age_key_file, resolve_common_args, resolve_editor,
    resolve_ignore_patterns, resolve_json, resolve_log_level, resolve_recipients, ConfigFile,
    ConfigFormat,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tempfile::tempdir;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_config_format_from_path() {
    assert_eq!(
        ConfigFormat::from_path(Path::new("config.toml")),
        Some(ConfigFormat::Toml)
    );
    assert_eq!(
        ConfigFormat::from_path(Path::new("config.yaml")),
        Some(ConfigFormat::Yaml)
    );
    assert_eq!(
        ConfigFormat::from_path(Path::new("config.yml")),
        Some(ConfigFormat::Yaml)
    );
    assert_eq!(
        ConfigFormat::from_path(Path::new("config.json")),
        Some(ConfigFormat::Json)
    );
    assert_eq!(ConfigFormat::from_path(Path::new("config.txt")), None);
}

#[test]
fn test_parse_multi_format_configs() {
    let toml_str = r#"
source = "/path/to/dotfiles"
target = "/custom/home"
age_key_file = "/path/to/key.txt"
recipients = ["age1test1", "age1test2"]
packages = ["zsh", "git"]
editor = "vim"
ignore = [".git", "*.swp"]
json = true
log_level = "warn"
"#;

    let yaml_str = r#"
source: /path/to/dotfiles
target: /custom/home
age_key_file: /path/to/key.txt
recipients:
  - age1test1
  - age1test2
packages:
  - zsh
  - git
editor: vim
ignore:
  - .git
  - "*.swp"
json: true
log_level: warn
"#;

    let json_str = r#"{
  "source": "/path/to/dotfiles",
  "target": "/custom/home",
  "age_key_file": "/path/to/key.txt",
  "recipients": ["age1test1", "age1test2"],
  "packages": ["zsh", "git"],
  "editor": "vim",
  "ignore": [".git", "*.swp"],
  "json": true,
  "log_level": "warn"
}"#;

    let cfg_toml = ConfigFile::parse(toml_str, ConfigFormat::Toml).unwrap();
    let cfg_yaml = ConfigFile::parse(yaml_str, ConfigFormat::Yaml).unwrap();
    let cfg_json = ConfigFile::parse(json_str, ConfigFormat::Json).unwrap();

    assert_eq!(cfg_toml, cfg_yaml);
    assert_eq!(cfg_yaml, cfg_json);

    assert_eq!(cfg_toml.source, Some(PathBuf::from("/path/to/dotfiles")));
    assert_eq!(cfg_toml.target, Some(PathBuf::from("/custom/home")));
    assert_eq!(
        cfg_toml.age_key_file,
        Some(PathBuf::from("/path/to/key.txt"))
    );
    assert_eq!(
        cfg_toml.recipients.as_ref().unwrap().to_recipients(),
        vec!["age1test1".to_string(), "age1test2".to_string()]
    );
    assert_eq!(
        cfg_toml.packages,
        Some(vec!["zsh".to_string(), "git".to_string()])
    );
    assert_eq!(cfg_toml.editor, Some("vim".to_string()));
    assert_eq!(
        cfg_toml.ignore,
        Some(vec![".git".to_string(), "*.swp".to_string()])
    );
    assert_eq!(cfg_toml.json, Some(true));
    assert_eq!(cfg_toml.log_level, Some("warn".to_string()));
}

#[test]
fn test_recipients_single_string_support() {
    let toml_str = r#"
recipients = "age1singlekey"
"#;
    let cfg = ConfigFile::parse(toml_str, ConfigFormat::Toml).unwrap();
    assert_eq!(
        cfg.recipients.unwrap().to_recipients(),
        vec!["age1singlekey".to_string()]
    );
}

#[test]
fn test_default_config_discovery() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let temp = tempdir().unwrap();
    let xdg_dir = temp.path().join("xdg");
    let enstow_dir = xdg_dir.join("enstow");
    fs::create_dir_all(&enstow_dir).unwrap();

    let config_file = enstow_dir.join("config.toml");
    fs::write(&config_file, "source = '/discovered/path'\n").unwrap();

    std::env::set_var("XDG_CONFIG_HOME", xdg_dir.to_str().unwrap());
    let discovered = ConfigFile::load_default().unwrap();
    std::env::remove_var("XDG_CONFIG_HOME");

    assert!(discovered.is_some());
    let (found_path, cfg) = discovered.unwrap();
    assert_eq!(found_path, config_file);
    assert_eq!(cfg.source, Some(PathBuf::from("/discovered/path")));
}

#[test]
fn test_explicit_config_override() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let temp = tempdir().unwrap();
    let custom_config = temp.path().join("custom.json");
    fs::write(&custom_config, r#"{"source": "/from/custom/json"}"#).unwrap();

    // 1. Via explicit path
    let loaded = load_config(Some(&custom_config)).unwrap();
    assert!(loaded.is_some());
    let (_, cfg) = loaded.unwrap();
    assert_eq!(cfg.source, Some(PathBuf::from("/from/custom/json")));

    // 2. Via ENSTOW_CONFIG environment variable
    std::env::set_var("ENSTOW_CONFIG", custom_config.to_str().unwrap());
    let env_loaded = load_config(None).unwrap();
    std::env::remove_var("ENSTOW_CONFIG");
    assert!(env_loaded.is_some());
    let (_, cfg) = env_loaded.unwrap();
    assert_eq!(cfg.source, Some(PathBuf::from("/from/custom/json")));
}

#[test]
fn test_precedence_hierarchy() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let orig_age_key = std::env::var("SOPS_AGE_KEY_FILE").ok();
    let orig_source = std::env::var("ENSTOW_SOURCE").ok();
    let orig_target = std::env::var("ENSTOW_TARGET").ok();
    let orig_recipients = std::env::var("SOPS_AGE_RECIPIENTS").ok();
    let orig_editor = std::env::var("EDITOR").ok();
    let orig_visual = std::env::var("VISUAL").ok();
    let orig_packages = std::env::var("ENSTOW_PACKAGES").ok();

    std::env::remove_var("SOPS_AGE_KEY_FILE");
    std::env::remove_var("ENSTOW_SOURCE");
    std::env::remove_var("ENSTOW_TARGET");
    std::env::remove_var("SOPS_AGE_RECIPIENTS");
    std::env::remove_var("EDITOR");
    std::env::remove_var("VISUAL");
    std::env::remove_var("ENSTOW_PACKAGES");

    let temp = tempdir().unwrap();
    let config_path = temp.path().join("config.toml");
    fs::write(
        &config_path,
        r#"
source = "/from/config/source"
target = "/from/config/target"
age_key_file = "/from/config/key"
editor = "config_editor"
packages = ["pkg_config"]
ignore = ["ignore_config"]
recipients = ["recipient_config"]
"#,
    )
    .unwrap();
    let config = ConfigFile::load_from_path(&config_path).unwrap();

    // Test 1: Config file overrides built-in defaults when CLI and Env are absent
    let empty_cli = CommonArgs::default();
    let resolved = resolve_common_args(&empty_cli, Some(&config));
    assert_eq!(resolved.source, PathBuf::from("/from/config/source"));
    assert_eq!(resolved.target, PathBuf::from("/from/config/target"));
    assert_eq!(
        resolved.age_key_file,
        Some(PathBuf::from("/from/config/key"))
    );
    assert_eq!(resolved.packages, vec!["pkg_config".to_string()]);
    assert_eq!(resolved.ignore, vec!["ignore_config".to_string()]);
    assert_eq!(
        resolve_editor(None, Some(&config)),
        Some("config_editor".to_string())
    );
    assert_eq!(
        resolve_recipients(&[], Some(&config)),
        vec!["recipient_config".to_string()]
    );

    // Test 2: Env vars override config file
    std::env::set_var("ENSTOW_SOURCE", "/from/env/source");
    std::env::set_var("ENSTOW_TARGET", "/from/env/target");
    std::env::set_var("SOPS_AGE_KEY_FILE", "/from/env/key");
    std::env::set_var("SOPS_AGE_RECIPIENTS", "recipient_env1,recipient_env2");
    std::env::set_var("EDITOR", "env_editor");
    std::env::set_var("ENSTOW_PACKAGES", "pkg_env1,pkg_env2");

    let resolved_env = resolve_common_args(&empty_cli, Some(&config));
    assert_eq!(resolved_env.source, PathBuf::from("/from/env/source"));
    assert_eq!(resolved_env.target, PathBuf::from("/from/env/target"));
    assert_eq!(
        resolved_env.age_key_file,
        Some(PathBuf::from("/from/env/key"))
    );
    assert_eq!(
        resolved_env.packages,
        vec!["pkg_env1".to_string(), "pkg_env2".to_string()]
    );
    assert_eq!(
        resolve_editor(None, Some(&config)),
        Some("env_editor".to_string())
    );
    assert_eq!(
        resolve_recipients(&[], Some(&config)),
        vec!["recipient_env1".to_string(), "recipient_env2".to_string()]
    );

    // Test 3: CLI args override env vars and config file
    let cli_args = CommonArgs {
        source: Some(PathBuf::from("/from/cli/source")),
        target: Some(PathBuf::from("/from/cli/target")),
        dry_run: true,
        force: true,
        prune: false,
        age_key_file: Some(PathBuf::from("/from/cli/key")),
        packages: vec!["pkg_cli".to_string()],
        ignore: vec![],
        ..Default::default()
    };

    let resolved_cli = resolve_common_args(&cli_args, Some(&config));
    assert_eq!(resolved_cli.source, PathBuf::from("/from/cli/source"));
    assert_eq!(resolved_cli.target, PathBuf::from("/from/cli/target"));
    assert_eq!(
        resolved_cli.age_key_file,
        Some(PathBuf::from("/from/cli/key"))
    );
    assert_eq!(resolved_cli.packages, vec!["pkg_cli".to_string()]);
    assert_eq!(
        resolve_editor(Some("cli_editor"), Some(&config)),
        Some("cli_editor".to_string())
    );
    assert_eq!(
        resolve_recipients(&["recipient_cli".to_string()], Some(&config)),
        vec!["recipient_cli".to_string()]
    );

    // Clean up env
    std::env::remove_var("ENSTOW_SOURCE");
    std::env::remove_var("ENSTOW_TARGET");
    std::env::remove_var("SOPS_AGE_KEY_FILE");
    std::env::remove_var("SOPS_AGE_RECIPIENTS");
    std::env::remove_var("EDITOR");
    std::env::remove_var("ENSTOW_PACKAGES");

    if let Some(v) = orig_age_key {
        std::env::set_var("SOPS_AGE_KEY_FILE", v);
    }
    if let Some(v) = orig_source {
        std::env::set_var("ENSTOW_SOURCE", v);
    }
    if let Some(v) = orig_target {
        std::env::set_var("ENSTOW_TARGET", v);
    }
    if let Some(v) = orig_recipients {
        std::env::set_var("SOPS_AGE_RECIPIENTS", v);
    }
    if let Some(v) = orig_editor {
        std::env::set_var("EDITOR", v);
    }
    if let Some(v) = orig_visual {
        std::env::set_var("VISUAL", v);
    }
    if let Some(v) = orig_packages {
        std::env::set_var("ENSTOW_PACKAGES", v);
    }
}

#[test]
fn test_enstow_env_aliases_precedence() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let orig_enstow_age_key = std::env::var("ENSTOW_AGE_KEY_FILE").ok();
    let orig_sops_age_key = std::env::var("SOPS_AGE_KEY_FILE").ok();
    let orig_enstow_recipients = std::env::var("ENSTOW_RECIPIENTS").ok();
    let orig_sops_recipients = std::env::var("SOPS_AGE_RECIPIENTS").ok();
    let orig_enstow_editor = std::env::var("ENSTOW_EDITOR").ok();
    let orig_visual = std::env::var("VISUAL").ok();
    let orig_editor = std::env::var("EDITOR").ok();

    std::env::remove_var("ENSTOW_AGE_KEY_FILE");
    std::env::remove_var("SOPS_AGE_KEY_FILE");
    std::env::remove_var("ENSTOW_RECIPIENTS");
    std::env::remove_var("SOPS_AGE_RECIPIENTS");
    std::env::remove_var("ENSTOW_EDITOR");
    std::env::remove_var("VISUAL");
    std::env::remove_var("EDITOR");

    // 1. Fallback behavior: SOPS_* and VISUAL/EDITOR work when ENSTOW_* unset
    std::env::set_var("SOPS_AGE_KEY_FILE", "/sops/key");
    std::env::set_var("SOPS_AGE_RECIPIENTS", "sops_recip1, sops_recip2");
    std::env::set_var("EDITOR", "editor_fallback");

    assert_eq!(
        resolve_age_key_file(None, None),
        Some(PathBuf::from("/sops/key"))
    );
    assert_eq!(
        resolve_recipients(&[], None),
        vec!["sops_recip1".to_string(), "sops_recip2".to_string()]
    );
    assert_eq!(
        resolve_editor(None, None),
        Some("editor_fallback".to_string())
    );

    // 2. ENSTOW_* aliases take precedence over external vars
    std::env::set_var("ENSTOW_AGE_KEY_FILE", "/enstow/key");
    std::env::set_var("ENSTOW_RECIPIENTS", "enstow_recip1, enstow_recip2");
    std::env::set_var("ENSTOW_EDITOR", "enstow_editor");
    std::env::set_var("VISUAL", "visual_editor");

    assert_eq!(
        resolve_age_key_file(None, None),
        Some(PathBuf::from("/enstow/key"))
    );
    assert_eq!(
        resolve_recipients(&[], None),
        vec!["enstow_recip1".to_string(), "enstow_recip2".to_string()]
    );
    assert_eq!(
        resolve_editor(None, None),
        Some("enstow_editor".to_string())
    );

    let empty_cli = CommonArgs::default();
    let resolved = resolve_common_args(&empty_cli, None);
    assert_eq!(resolved.age_key_file, Some(PathBuf::from("/enstow/key")));

    // Clean up
    std::env::remove_var("ENSTOW_AGE_KEY_FILE");
    std::env::remove_var("SOPS_AGE_KEY_FILE");
    std::env::remove_var("ENSTOW_RECIPIENTS");
    std::env::remove_var("SOPS_AGE_RECIPIENTS");
    std::env::remove_var("ENSTOW_EDITOR");
    std::env::remove_var("VISUAL");
    std::env::remove_var("EDITOR");

    if let Some(v) = orig_enstow_age_key {
        std::env::set_var("ENSTOW_AGE_KEY_FILE", v);
    }
    if let Some(v) = orig_sops_age_key {
        std::env::set_var("SOPS_AGE_KEY_FILE", v);
    }
    if let Some(v) = orig_enstow_recipients {
        std::env::set_var("ENSTOW_RECIPIENTS", v);
    }
    if let Some(v) = orig_sops_recipients {
        std::env::set_var("SOPS_AGE_RECIPIENTS", v);
    }
    if let Some(v) = orig_enstow_editor {
        std::env::set_var("ENSTOW_EDITOR", v);
    }
    if let Some(v) = orig_visual {
        std::env::set_var("VISUAL", v);
    }
    if let Some(v) = orig_editor {
        std::env::set_var("EDITOR", v);
    }
}

#[test]
fn test_parse_dry_run_and_force() {
    let toml_str = r#"
dry_run = true
force = true
"#;
    let yaml_str = r#"
dry_run: true
force: true
"#;
    let json_str = r#"{
  "dry_run": true,
  "force": true
}"#;

    let cfg_toml = ConfigFile::parse(toml_str, ConfigFormat::Toml).unwrap();
    let cfg_yaml = ConfigFile::parse(yaml_str, ConfigFormat::Yaml).unwrap();
    let cfg_json = ConfigFile::parse(json_str, ConfigFormat::Json).unwrap();

    assert_eq!(cfg_toml.dry_run, Some(true));
    assert_eq!(cfg_toml.force, Some(true));
    assert_eq!(cfg_toml, cfg_yaml);
    assert_eq!(cfg_yaml, cfg_json);
}

#[test]
fn test_parse_backup_and_backup_dir() {
    let toml_str = r#"
backup = true
backup_dir = "/custom/backup/dir"
"#;
    let cfg_toml = ConfigFile::parse(toml_str, ConfigFormat::Toml).unwrap();
    assert_eq!(cfg_toml.backup, Some(true));
    assert_eq!(
        cfg_toml.backup_dir,
        Some(PathBuf::from("/custom/backup/dir"))
    );

    let yaml_str = r#"
backup: false
backup_dir: /yaml/backup
"#;
    let cfg_yaml = ConfigFile::parse(yaml_str, ConfigFormat::Yaml).unwrap();
    assert_eq!(cfg_yaml.backup, Some(false));
    assert_eq!(cfg_yaml.backup_dir, Some(PathBuf::from("/yaml/backup")));

    let json_str = r#"{
  "backup": true,
  "backup_dir": "/json/backup"
}"#;
    let cfg_json = ConfigFile::parse(json_str, ConfigFormat::Json).unwrap();
    assert_eq!(cfg_json.backup, Some(true));
    assert_eq!(cfg_json.backup_dir, Some(PathBuf::from("/json/backup")));
}

#[test]
fn test_backup_precedence_hierarchy() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let orig_backup = std::env::var("ENSTOW_BACKUP").ok();
    let orig_backup_dir = std::env::var("ENSTOW_BACKUP_DIR").ok();

    std::env::remove_var("ENSTOW_BACKUP");
    std::env::remove_var("ENSTOW_BACKUP_DIR");

    let empty_cli = CommonArgs::default();

    // 1. Defaults when nothing is set
    let resolved = resolve_common_args(&empty_cli, None);
    assert!(!resolved.backup);
    assert_eq!(resolved.backup_dir, resolved.target.join(".enstow-backup"));

    // 2. Config file sets backup and backup_dir
    let toml_str = r#"
backup = true
backup_dir = "/from/config/backup"
"#;
    let config = ConfigFile::parse(toml_str, ConfigFormat::Toml).unwrap();
    let resolved = resolve_common_args(&empty_cli, Some(&config));
    assert!(resolved.backup);
    assert_eq!(resolved.backup_dir, PathBuf::from("/from/config/backup"));

    // 3. Env var overrides config file
    std::env::set_var("ENSTOW_BACKUP", "false");
    std::env::set_var("ENSTOW_BACKUP_DIR", "/from/env/backup");
    let resolved = resolve_common_args(&empty_cli, Some(&config));
    assert!(!resolved.backup);
    assert_eq!(resolved.backup_dir, PathBuf::from("/from/env/backup"));

    // 3b. Env var ENSTOW_BACKUP=1 enables backup
    std::env::set_var("ENSTOW_BACKUP", "1");
    let resolved = resolve_common_args(&empty_cli, Some(&config));
    assert!(resolved.backup);

    // 4. CLI flags override env var and config file
    std::env::set_var("ENSTOW_BACKUP", "0");
    std::env::set_var("ENSTOW_BACKUP_DIR", "/from/env/backup");
    let cli_flags = CommonArgs {
        backup: true,
        backup_dir: Some(PathBuf::from("/from/cli/backup")),
        ..Default::default()
    };
    let resolved = resolve_common_args(&cli_flags, Some(&config));
    assert!(resolved.backup);
    assert_eq!(resolved.backup_dir, PathBuf::from("/from/cli/backup"));

    // Clean up
    std::env::remove_var("ENSTOW_BACKUP");
    std::env::remove_var("ENSTOW_BACKUP_DIR");
    if let Some(v) = orig_backup {
        std::env::set_var("ENSTOW_BACKUP", v);
    }
    if let Some(v) = orig_backup_dir {
        std::env::set_var("ENSTOW_BACKUP_DIR", v);
    }
}

#[test]
fn test_cli_parsing_backup_flags() {
    // Top-level CLI short flag -b
    let cli = Cli::try_parse_from(["enstow", "-b"]).unwrap();
    assert!(cli.common.backup);
    assert!(cli.common.backup_dir.is_none());

    // Top-level CLI long flag --backup and --backup-dir
    let cli = Cli::try_parse_from(["enstow", "--backup", "--backup-dir", "/tmp/backups"]).unwrap();
    assert!(cli.common.backup);
    assert_eq!(cli.common.backup_dir, Some(PathBuf::from("/tmp/backups")));

    // Subcommand Apply with -b and --backup-dir
    let cli = Cli::try_parse_from([
        "enstow",
        "apply",
        "-b",
        "--backup-dir",
        "/custom/apply_backup",
        "zsh",
    ])
    .unwrap();
    if let Some(Commands::Apply(args)) = cli.command {
        assert!(args.backup);
        assert_eq!(args.backup_dir, Some(PathBuf::from("/custom/apply_backup")));
        assert_eq!(args.packages, vec!["zsh".to_string()]);
    } else {
        panic!("Expected Commands::Apply");
    }

    // Subcommand Restow with -b
    let cli = Cli::try_parse_from(["enstow", "restow", "-b"]).unwrap();
    if let Some(Commands::Restow(args)) = cli.command {
        assert!(args.backup);
    } else {
        panic!("Expected Commands::Restow");
    }
}

#[test]
fn test_dry_run_and_force_precedence_hierarchy() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let orig_dry_run = std::env::var("ENSTOW_DRY_RUN").ok();
    let orig_force = std::env::var("ENSTOW_FORCE").ok();

    std::env::remove_var("ENSTOW_DRY_RUN");
    std::env::remove_var("ENSTOW_FORCE");

    let empty_cli = CommonArgs::default();

    // 1. Defaults are false when nothing is set
    let resolved = resolve_common_args(&empty_cli, None);
    assert!(!resolved.dry_run);
    assert!(!resolved.force);

    // 2. Config file sets dry_run = true, force = true
    let toml_str = r#"
dry_run = true
force = true
"#;
    let config = ConfigFile::parse(toml_str, ConfigFormat::Toml).unwrap();
    let resolved = resolve_common_args(&empty_cli, Some(&config));
    assert!(resolved.dry_run);
    assert!(resolved.force);

    // 3. Env var overrides config file:
    // 3a. Env disables dry_run and force with "0" / "false"
    std::env::set_var("ENSTOW_DRY_RUN", "0");
    std::env::set_var("ENSTOW_FORCE", "false");
    let resolved = resolve_common_args(&empty_cli, Some(&config));
    assert!(!resolved.dry_run);
    assert!(!resolved.force);

    // 3b. Env enables dry_run and force with "1" / "true" over config false
    let toml_false = r#"
dry_run = false
force = false
"#;
    let config_false = ConfigFile::parse(toml_false, ConfigFormat::Toml).unwrap();
    std::env::set_var("ENSTOW_DRY_RUN", "1");
    std::env::set_var("ENSTOW_FORCE", "true");
    let resolved = resolve_common_args(&empty_cli, Some(&config_false));
    assert!(resolved.dry_run);
    assert!(resolved.force);

    // 4. CLI flags override env var and config file
    std::env::set_var("ENSTOW_DRY_RUN", "0");
    std::env::set_var("ENSTOW_FORCE", "0");
    let cli_flags = CommonArgs {
        dry_run: true,
        force: true,
        prune: false,
        ..Default::default()
    };
    let resolved = resolve_common_args(&cli_flags, Some(&config_false));
    assert!(resolved.dry_run);
    assert!(resolved.force);

    // Clean up
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
fn test_cli_parsing_ignore_flags() {
    // 1. Root apply / default command
    let cli = Cli::try_parse_from(["enstow", "-i", "*.bak", "--ignore", "*.tmp"]).unwrap();
    assert_eq!(
        cli.common.ignore,
        vec!["*.bak".to_string(), "*.tmp".to_string()]
    );

    // 2. Explicit apply subcommand
    let cli = Cli::try_parse_from(["enstow", "apply", "-i", "*.bak", "-i", "*.tmp"]).unwrap();
    match cli.command {
        Some(Commands::Apply(args)) => {
            assert_eq!(args.ignore, vec!["*.bak".to_string(), "*.tmp".to_string()]);
        }
        _ => panic!("Expected Commands::Apply"),
    }

    // 3. Restow subcommand
    let cli = Cli::try_parse_from(["enstow", "restow", "-i", "*.bak"]).unwrap();
    match cli.command {
        Some(Commands::Restow(args)) => {
            assert_eq!(args.ignore, vec!["*.bak".to_string()]);
        }
        _ => panic!("Expected Commands::Restow"),
    }

    // 4. Unstow subcommand
    let cli = Cli::try_parse_from(["enstow", "unstow", "-i", "*.bak"]).unwrap();
    match cli.command {
        Some(Commands::Unstow(args)) => {
            assert_eq!(args.ignore, vec!["*.bak".to_string()]);
        }
        _ => panic!("Expected Commands::Unstow"),
    }

    // 5. Status subcommand
    let cli = Cli::try_parse_from(["enstow", "status", "-i", "*.bak"]).unwrap();
    match cli.command {
        Some(Commands::Status { common, .. }) => {
            assert_eq!(common.ignore, vec!["*.bak".to_string()]);
        }
        _ => panic!("Expected Commands::Status"),
    }
}

#[test]
fn test_resolve_ignore_patterns() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let orig_ignore = std::env::var("ENSTOW_IGNORE").ok();
    std::env::remove_var("ENSTOW_IGNORE");

    // 1. Empty everywhere
    assert_eq!(resolve_ignore_patterns(&[], None), Vec::<String>::new());

    // 2. CLI flags alone
    let cli = vec!["*.bak".to_string(), "*.tmp".to_string()];
    assert_eq!(
        resolve_ignore_patterns(&cli, None),
        vec!["*.bak".to_string(), "*.tmp".to_string()]
    );

    // 3. ENSTOW_IGNORE alone (comma-separated and colon-separated)
    std::env::set_var("ENSTOW_IGNORE", "*.bak,*.tmp:*.swp");
    assert_eq!(
        resolve_ignore_patterns(&[], None),
        vec![
            "*.bak".to_string(),
            "*.tmp".to_string(),
            "*.swp".to_string()
        ]
    );

    // 4. Config file alone
    std::env::remove_var("ENSTOW_IGNORE");
    let cfg = ConfigFile {
        ignore: Some(vec!["*.cfg_ignore".to_string()]),
        ..Default::default()
    };
    assert_eq!(
        resolve_ignore_patterns(&[], Some(&cfg)),
        vec!["*.cfg_ignore".to_string()]
    );

    // 5. Additive merge with deduplication across CLI, ENSTOW_IGNORE, and Config
    let cli = vec!["*.bak".to_string(), "*.tmp".to_string()];
    std::env::set_var("ENSTOW_IGNORE", " *.tmp, *.log : *.swp ");
    let cfg = ConfigFile {
        ignore: Some(vec!["*.swp".to_string(), "*.cache".to_string()]),
        ..Default::default()
    };
    assert_eq!(
        resolve_ignore_patterns(&cli, Some(&cfg)),
        vec![
            "*.bak".to_string(),
            "*.tmp".to_string(),
            "*.log".to_string(),
            "*.swp".to_string(),
            "*.cache".to_string()
        ]
    );

    std::env::remove_var("ENSTOW_IGNORE");
    if let Some(v) = orig_ignore {
        std::env::set_var("ENSTOW_IGNORE", v);
    }
}

#[test]
fn test_json_output_precedence_hierarchy() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let orig_json = std::env::var("ENSTOW_JSON").ok();
    std::env::remove_var("ENSTOW_JSON");

    // 1. Defaults to false when CLI, env, and config are not set
    assert!(!resolve_json(false, None));

    // 2. Config file alone sets json = true
    let toml_true = r#"
json = true
"#;
    let config_true = ConfigFile::parse(toml_true, ConfigFormat::Toml).unwrap();
    assert!(resolve_json(false, Some(&config_true)));

    // 2b. Config file sets output = "json"
    let toml_output = r#"
output = "json"
"#;
    let config_output = ConfigFile::parse(toml_output, ConfigFormat::Toml).unwrap();
    assert!(resolve_json(false, Some(&config_output)));

    // 2c. Config file explicitly sets json = false
    let toml_false = r#"
json = false
"#;
    let config_false = ConfigFile::parse(toml_false, ConfigFormat::Toml).unwrap();
    assert!(!resolve_json(false, Some(&config_false)));

    // 3. Env var ENSTOW_JSON overrides config file:
    // 3a. ENSTOW_JSON="0" or "false" disables JSON even if config has json = true
    std::env::set_var("ENSTOW_JSON", "0");
    assert!(!resolve_json(false, Some(&config_true)));
    std::env::set_var("ENSTOW_JSON", "false");
    assert!(!resolve_json(false, Some(&config_true)));

    // 3b. ENSTOW_JSON="1" or "true" enables JSON even if config has json = false
    std::env::set_var("ENSTOW_JSON", "1");
    assert!(resolve_json(false, Some(&config_false)));
    std::env::set_var("ENSTOW_JSON", "true");
    assert!(resolve_json(false, Some(&config_false)));

    // 3c. ENSTOW_JSON="1" enables JSON with no config file
    assert!(resolve_json(false, None));

    // 4. CLI explicit flag overrides ENSTOW_JSON and config file
    // Even if ENSTOW_JSON=0 and config has json = false, cli_json = true enables JSON
    std::env::set_var("ENSTOW_JSON", "0");
    assert!(resolve_json(true, Some(&config_false)));

    std::env::set_var("ENSTOW_JSON", "false");
    assert!(resolve_json(true, Some(&config_false)));

    assert!(resolve_json(true, None));

    // Clean up
    std::env::remove_var("ENSTOW_JSON");
    if let Some(v) = orig_json {
        std::env::set_var("ENSTOW_JSON", v);
    }
}

#[test]
fn test_log_level_precedence_hierarchy() {
    let _lock = ENV_MUTEX.lock().unwrap();

    let orig_enstow_log = std::env::var("ENSTOW_LOG_LEVEL").ok();
    let orig_rust_log = std::env::var("RUST_LOG").ok();

    std::env::remove_var("ENSTOW_LOG_LEVEL");
    std::env::remove_var("RUST_LOG");

    // 1. Default fallback is "info"
    assert_eq!(resolve_log_level(None, 0, 0, None), "info");

    // 2. Config file alone
    let cfg = ConfigFile {
        log_level: Some("warn".to_string()),
        ..Default::default()
    };
    assert_eq!(resolve_log_level(None, 0, 0, Some(&cfg)), "warn");

    // Case insensitivity
    let cfg_upper = ConfigFile {
        log_level: Some("ERROR".to_string()),
        ..Default::default()
    };
    assert_eq!(resolve_log_level(None, 0, 0, Some(&cfg_upper)), "error");

    // Empty config string falls back to default
    let cfg_empty = ConfigFile {
        log_level: Some("   ".to_string()),
        ..Default::default()
    };
    assert_eq!(resolve_log_level(None, 0, 0, Some(&cfg_empty)), "info");

    // 3. Fallback to RUST_LOG environment variable overrides config file
    std::env::set_var("RUST_LOG", "debug");
    assert_eq!(resolve_log_level(None, 0, 0, Some(&cfg)), "debug");
    assert_eq!(resolve_log_level(None, 0, 0, None), "debug");

    // 4. ENSTOW_LOG_LEVEL environment variable overrides RUST_LOG and config file
    std::env::set_var("ENSTOW_LOG_LEVEL", "error");
    assert_eq!(resolve_log_level(None, 0, 0, Some(&cfg)), "error");
    assert_eq!(resolve_log_level(None, 0, 0, None), "error");

    // Empty ENSTOW_LOG_LEVEL falls back to RUST_LOG
    std::env::set_var("ENSTOW_LOG_LEVEL", "");
    assert_eq!(resolve_log_level(None, 0, 0, Some(&cfg)), "debug");

    // Clean env for CLI testing
    std::env::set_var("ENSTOW_LOG_LEVEL", "error");
    std::env::set_var("RUST_LOG", "trace");

    // 5. CLI -v / --verbose overrides env vars and config
    // -v -> "debug"
    assert_eq!(resolve_log_level(None, 1, 0, Some(&cfg)), "debug");
    // -vv -> "trace"
    assert_eq!(resolve_log_level(None, 2, 0, Some(&cfg)), "trace");
    assert_eq!(resolve_log_level(None, 3, 0, Some(&cfg)), "trace");

    // 6. CLI -q / --quiet overrides env vars and config
    // -q -> "warn"
    assert_eq!(resolve_log_level(None, 0, 1, Some(&cfg)), "warn");
    // -qq -> "error"
    assert_eq!(resolve_log_level(None, 0, 2, Some(&cfg)), "error");

    // 7. CLI --log-level overrides everything
    assert_eq!(resolve_log_level(Some("debug"), 0, 0, Some(&cfg)), "debug");
    assert_eq!(resolve_log_level(Some("INFO"), 0, 0, Some(&cfg)), "info");
    assert_eq!(resolve_log_level(Some("off"), 2, 2, Some(&cfg)), "off");

    // Clean up
    std::env::remove_var("ENSTOW_LOG_LEVEL");
    std::env::remove_var("RUST_LOG");
    if let Some(v) = orig_enstow_log {
        std::env::set_var("ENSTOW_LOG_LEVEL", v);
    }
    if let Some(v) = orig_rust_log {
        std::env::set_var("RUST_LOG", v);
    }
}

#[test]
fn test_config_error_paths_and_fallbacks() {
    let _lock = ENV_MUTEX.lock().unwrap();

    let tmp = tempfile::tempdir().unwrap();

    // 1. Unsupported configuration file extension (file must exist to read content)
    let tmp_file = tmp.path().join("config.unknown");
    std::fs::write(&tmp_file, "some content").unwrap();
    let err = ConfigFile::load_from_path(&tmp_file).unwrap_err();
    assert!(err.to_string().contains("Unsupported configuration format"));
    let err = load_config(Some(tmp.path())).unwrap_err();
    assert!(err.to_string().contains("is not a regular file"));

    // 4. ENSTOW_CONFIG pointing to directory
    let orig_enstow_cfg = std::env::var("ENSTOW_CONFIG").ok();
    std::env::set_var("ENSTOW_CONFIG", tmp.path());
    let err = load_config(None).unwrap_err();
    assert!(err
        .to_string()
        .contains("from ENSTOW_CONFIG is not a regular file"));

    // 5. ENSTOW_CONFIG pointing to nonexistent file
    std::env::set_var("ENSTOW_CONFIG", "nonexistent_from_env.toml");
    let err = load_config(None).unwrap_err();
    assert!(err.to_string().contains("from ENSTOW_CONFIG not found"));

    std::env::remove_var("ENSTOW_CONFIG");
    if let Some(v) = orig_enstow_cfg {
        std::env::set_var("ENSTOW_CONFIG", v);
    }

    // 6. parse_bool_env with invalid value
    std::env::set_var("ENSTOW_TEST_INVALID_BOOL", "not_a_bool");
    assert_eq!(parse_bool_env("ENSTOW_TEST_INVALID_BOOL"), None);
    std::env::remove_var("ENSTOW_TEST_INVALID_BOOL");

    // 7. resolve_json with config without json or output set
    let empty_cfg = ConfigFile::default();
    assert!(!resolve_json(false, Some(&empty_cfg)));

    // 8. resolve_editor fallbacks with empty env and empty strings
    let orig_enstow_ed = std::env::var("ENSTOW_EDITOR").ok();
    let orig_visual = std::env::var("VISUAL").ok();
    let orig_editor = std::env::var("EDITOR").ok();

    std::env::remove_var("ENSTOW_EDITOR");
    std::env::remove_var("VISUAL");
    std::env::remove_var("EDITOR");

    // All empty -> None
    assert_eq!(resolve_editor(Some("   "), None), None);
    assert_eq!(resolve_editor(None, None), None);

    // VISUAL fallback
    std::env::set_var("VISUAL", "vis_editor");
    assert_eq!(resolve_editor(None, None), Some("vis_editor".to_string()));
    std::env::set_var("VISUAL", "  ");
    assert_eq!(resolve_editor(None, None), None);

    // EDITOR fallback
    std::env::set_var("EDITOR", "std_editor");
    assert_eq!(resolve_editor(None, None), Some("std_editor".to_string()));
    std::env::set_var("EDITOR", "  ");
    assert_eq!(resolve_editor(None, None), None);

    // Config editor fallback with empty string
    let cfg_empty_ed = ConfigFile {
        editor: Some("   ".to_string()),
        ..Default::default()
    };
    assert_eq!(resolve_editor(None, Some(&cfg_empty_ed)), None);

    std::env::remove_var("ENSTOW_EDITOR");
    std::env::remove_var("VISUAL");
    std::env::remove_var("EDITOR");
    if let Some(v) = orig_enstow_ed {
        std::env::set_var("ENSTOW_EDITOR", v);
    }
    if let Some(v) = orig_visual {
        std::env::set_var("VISUAL", v);
    }
    if let Some(v) = orig_editor {
        std::env::set_var("EDITOR", v);
    }

    // 9. resolve_recipients fallbacks with empty env vars
    let orig_recs = std::env::var("ENSTOW_RECIPIENTS").ok();
    let orig_sops_recs = std::env::var("SOPS_AGE_RECIPIENTS").ok();

    std::env::set_var("ENSTOW_RECIPIENTS", "   ");
    std::env::set_var("SOPS_AGE_RECIPIENTS", "   ");
    let cfg_no_recips = ConfigFile {
        recipients: Some(enstow::config::RecipientsConfig::List(vec![])),
        ..Default::default()
    };
    assert_eq!(
        resolve_recipients(&[], Some(&cfg_no_recips)),
        Vec::<String>::new()
    );

    std::env::remove_var("ENSTOW_RECIPIENTS");
    std::env::remove_var("SOPS_AGE_RECIPIENTS");
    if let Some(v) = orig_recs {
        std::env::set_var("ENSTOW_RECIPIENTS", v);
    }
    if let Some(v) = orig_sops_recs {
        std::env::set_var("SOPS_AGE_RECIPIENTS", v);
    }

    // 10. resolve_age_key_file with empty env vars
    let orig_k1 = std::env::var("ENSTOW_AGE_KEY_FILE").ok();
    let orig_k2 = std::env::var("SOPS_AGE_KEY_FILE").ok();

    std::env::set_var("ENSTOW_AGE_KEY_FILE", "   ");
    std::env::set_var("SOPS_AGE_KEY_FILE", "   ");
    let cfg_key = ConfigFile {
        age_key_file: Some(PathBuf::from("/cfg/key.txt")),
        ..Default::default()
    };
    assert_eq!(
        resolve_age_key_file(None, Some(&cfg_key)),
        Some(PathBuf::from("/cfg/key.txt"))
    );

    std::env::remove_var("ENSTOW_AGE_KEY_FILE");
    std::env::remove_var("SOPS_AGE_KEY_FILE");
    if let Some(v) = orig_k1 {
        std::env::set_var("ENSTOW_AGE_KEY_FILE", v);
    }
    if let Some(v) = orig_k2 {
        std::env::set_var("SOPS_AGE_KEY_FILE", v);
    }

    // 11. resolve_common_args with empty whitespace env vars falling back to config
    let orig_src = std::env::var("ENSTOW_SOURCE").ok();
    let orig_tgt = std::env::var("ENSTOW_TARGET").ok();
    let orig_pkgs = std::env::var("ENSTOW_PACKAGES").ok();
    let orig_bdir = std::env::var("ENSTOW_BACKUP_DIR").ok();

    std::env::set_var("ENSTOW_SOURCE", "   ");
    std::env::set_var("ENSTOW_TARGET", "   ");
    std::env::set_var("ENSTOW_PACKAGES", "   ");
    std::env::set_var("ENSTOW_BACKUP_DIR", "   ");

    let cfg_env_fallback = ConfigFile {
        source: Some(PathBuf::from("/fallback/source")),
        target: Some(PathBuf::from("/fallback/target")),
        packages: Some(vec!["fallback_pkg".to_string()]),
        backup_dir: Some(PathBuf::from("/fallback/backup")),
        ..Default::default()
    };

    let empty_cli = CommonArgs::default();
    let resolved = resolve_common_args(&empty_cli, Some(&cfg_env_fallback));
    assert_eq!(resolved.source, PathBuf::from("/fallback/source"));
    assert_eq!(resolved.target, PathBuf::from("/fallback/target"));
    assert_eq!(resolved.packages, vec!["fallback_pkg".to_string()]);
    assert_eq!(resolved.backup_dir, PathBuf::from("/fallback/backup"));

    std::env::remove_var("ENSTOW_SOURCE");
    std::env::remove_var("ENSTOW_TARGET");
    std::env::remove_var("ENSTOW_PACKAGES");
    std::env::remove_var("ENSTOW_BACKUP_DIR");
    if let Some(v) = orig_src {
        std::env::set_var("ENSTOW_SOURCE", v);
    }
    if let Some(v) = orig_tgt {
        std::env::set_var("ENSTOW_TARGET", v);
    }
    if let Some(v) = orig_pkgs {
        std::env::set_var("ENSTOW_PACKAGES", v);
    }
    if let Some(v) = orig_bdir {
        std::env::set_var("ENSTOW_BACKUP_DIR", v);
    }
}
