use clap::Parser;
use enstow::cli::{Cli, Commands, CommonArgs};
use enstow::config::{
    load_config, resolve_age_key_file, resolve_common_args, resolve_editor,
    resolve_ignore_patterns, resolve_recipients, ConfigFile, ConfigFormat,
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
"#;

    let json_str = r#"{
  "source": "/path/to/dotfiles",
  "target": "/custom/home",
  "age_key_file": "/path/to/key.txt",
  "recipients": ["age1test1", "age1test2"],
  "packages": ["zsh", "git"],
  "editor": "vim",
  "ignore": [".git", "*.swp"]
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
        age_key_file: Some(PathBuf::from("/from/cli/key")),
        packages: vec!["pkg_cli".to_string()],
        ignore: vec![],
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
