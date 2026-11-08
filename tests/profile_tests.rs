use clap::Parser;
use enstow::cli::{Cli, Commands, CommonArgs};
use enstow::config::{
    resolve_common_args, resolve_packages, resolve_profile, ConfigFile, ConfigFormat, ProfileConfig,
};
use enstow::stow::{execute_plan, plan_stow};
use std::collections::BTreeMap;
use std::fs;
use std::sync::Mutex;
use tempfile::tempdir;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_config_deserialization_profiles() {
    let toml_content = r#"
default_profile = "work"

[profiles.work]
packages = ["common", "git", "zsh", "work"]

[profiles.server]
packages = ["common", "bash", "server"]
"#;

    let cfg_toml = ConfigFile::parse(toml_content, ConfigFormat::Toml).unwrap();
    assert_eq!(cfg_toml.default_profile.as_deref(), Some("work"));
    let profiles = cfg_toml.profiles.expect("profiles should be parsed");
    assert_eq!(profiles.len(), 2);
    assert_eq!(
        profiles.get("work").unwrap().packages,
        vec!["common", "git", "zsh", "work"]
    );
    assert_eq!(
        profiles.get("server").unwrap().packages,
        vec!["common", "bash", "server"]
    );

    let yaml_content = r#"
default_profile: server
profiles:
  work:
    packages:
      - common
      - git
  server:
    packages:
      - common
      - server
"#;
    let cfg_yaml = ConfigFile::parse(yaml_content, ConfigFormat::Yaml).unwrap();
    assert_eq!(cfg_yaml.default_profile.as_deref(), Some("server"));
    let profiles_yaml = cfg_yaml.profiles.expect("yaml profiles should be parsed");
    assert_eq!(
        profiles_yaml.get("server").unwrap().packages,
        vec!["common", "server"]
    );

    let json_content = r#"
{
  "default_profile": "work",
  "profiles": {
    "work": {
      "packages": ["common", "work"]
    }
  }
}
"#;
    let cfg_json = ConfigFile::parse(json_content, ConfigFormat::Json).unwrap();
    assert_eq!(cfg_json.default_profile.as_deref(), Some("work"));
    let profiles_json = cfg_json.profiles.expect("json profiles should be parsed");
    assert_eq!(
        profiles_json.get("work").unwrap().packages,
        vec!["common", "work"]
    );
}

#[test]
fn test_cli_parsing_profile_flag() {
    let _lock = ENV_MUTEX.lock().unwrap();
    // 1. apply --profile
    let cli = Cli::try_parse_from(["enstow", "apply", "--profile", "work"]).unwrap();
    match cli.command {
        Some(Commands::Apply(args)) => {
            assert_eq!(args.profile.as_deref(), Some("work"));
        }
        other => panic!("Expected Commands::Apply, got {:?}", other),
    }

    // 2. restow --profile
    let cli = Cli::try_parse_from(["enstow", "restow", "--profile", "laptop"]).unwrap();
    match cli.command {
        Some(Commands::Restow(args)) => {
            assert_eq!(args.profile.as_deref(), Some("laptop"));
        }
        other => panic!("Expected Commands::Restow, got {:?}", other),
    }

    // 3. unstow --profile
    let cli = Cli::try_parse_from(["enstow", "unstow", "--profile", "server"]).unwrap();
    match cli.command {
        Some(Commands::Unstow(args)) => {
            assert_eq!(args.profile.as_deref(), Some("server"));
        }
        other => panic!("Expected Commands::Unstow, got {:?}", other),
    }

    // 4. status --profile
    let cli = Cli::try_parse_from(["enstow", "status", "--profile", "work"]).unwrap();
    match cli.command {
        Some(Commands::Status { common, .. }) => {
            assert_eq!(common.profile.as_deref(), Some("work"));
        }
        other => panic!("Expected Commands::Status, got {:?}", other),
    }

    // 5. diff --profile
    let cli = Cli::try_parse_from(["enstow", "diff", "--profile", "work"]).unwrap();
    match cli.command {
        Some(Commands::Diff { common, .. }) => {
            assert_eq!(common.profile.as_deref(), Some("work"));
        }
        other => panic!("Expected Commands::Diff, got {:?}", other),
    }

    // 6. default command with --profile
    let cli = Cli::try_parse_from(["enstow", "--profile", "work"]).unwrap();
    assert!(cli.command.is_none());
    assert_eq!(cli.common.profile.as_deref(), Some("work"));
}

#[test]
fn test_package_precedence_hierarchy() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let mut profiles = BTreeMap::new();
    profiles.insert(
        "work".to_string(),
        ProfileConfig {
            packages: vec!["common".into(), "git".into(), "work".into()],
        },
    );
    profiles.insert(
        "server".to_string(),
        ProfileConfig {
            packages: vec!["common".into(), "server".into()],
        },
    );

    let config = ConfigFile {
        default_profile: Some("server".to_string()),
        profiles: Some(profiles),
        packages: Some(vec!["global_pkg".to_string()]),
        ..Default::default()
    };

    // 1. Explicit CLI packages beat everything
    let res = resolve_packages(&["custom_pkg".to_string()], Some("work"), Some(&config)).unwrap();
    assert_eq!(res, vec!["custom_pkg"]);

    // 2. CLI --profile beats default_profile and config.packages
    let res = resolve_packages(&[], Some("work"), Some(&config)).unwrap();
    assert_eq!(res, vec!["common", "git", "work"]);

    // 3. Fallback to default_profile when no CLI packages and no CLI profile
    let res = resolve_packages(&[], None, Some(&config)).unwrap();
    assert_eq!(res, vec!["common", "server"]);

    // 4. Fallback to config.packages when no default_profile
    let config_no_default = ConfigFile {
        default_profile: None,
        profiles: config.profiles.clone(),
        packages: Some(vec!["global_pkg".to_string()]),
        ..Default::default()
    };
    let res = resolve_packages(&[], None, Some(&config_no_default)).unwrap();
    assert_eq!(res, vec!["global_pkg"]);

    // 5. Fallback to empty (all packages in source root)
    let empty_config = ConfigFile::default();
    let res = resolve_packages(&[], None, Some(&empty_config)).unwrap();
    assert!(res.is_empty());
}

#[test]
fn test_enstow_profile_env_var_support() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let mut profiles = BTreeMap::new();
    profiles.insert(
        "work".to_string(),
        ProfileConfig {
            packages: vec!["work_pkg".into()],
        },
    );
    let config = ConfigFile {
        profiles: Some(profiles),
        ..Default::default()
    };

    let orig = std::env::var("ENSTOW_PROFILE").ok();
    std::env::set_var("ENSTOW_PROFILE", "work");

    let res = resolve_packages(&[], None, Some(&config)).unwrap();
    assert_eq!(res, vec!["work_pkg"]);

    // Explicit CLI profile overrides ENSTOW_PROFILE
    let mut profiles2 = BTreeMap::new();
    profiles2.insert(
        "work".to_string(),
        ProfileConfig {
            packages: vec!["work_pkg".into()],
        },
    );
    profiles2.insert(
        "server".to_string(),
        ProfileConfig {
            packages: vec!["server_pkg".into()],
        },
    );
    let config2 = ConfigFile {
        profiles: Some(profiles2),
        ..Default::default()
    };

    let res = resolve_packages(&[], Some("server"), Some(&config2)).unwrap();
    assert_eq!(res, vec!["server_pkg"]);

    match orig {
        Some(v) => std::env::set_var("ENSTOW_PROFILE", v),
        None => std::env::remove_var("ENSTOW_PROFILE"),
    }
}

#[test]
fn test_unknown_profile_errors() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let mut profiles = BTreeMap::new();
    profiles.insert(
        "work".to_string(),
        ProfileConfig {
            packages: vec!["work_pkg".into()],
        },
    );
    profiles.insert(
        "server".to_string(),
        ProfileConfig {
            packages: vec!["server_pkg".into()],
        },
    );
    let config = ConfigFile {
        profiles: Some(profiles),
        ..Default::default()
    };

    // Unknown CLI profile
    let err = resolve_packages(&[], Some("nonexistent"), Some(&config)).unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("Unknown profile 'nonexistent'"),
        "got: {}",
        err_msg
    );
    assert!(err_msg.contains("server"), "got: {}", err_msg);
    assert!(err_msg.contains("work"), "got: {}", err_msg);

    // Unknown profile when config has no profiles
    let empty_config = ConfigFile::default();
    let err2 = resolve_packages(&[], Some("work"), Some(&empty_config)).unwrap_err();
    assert!(err2.to_string().contains("Unknown profile 'work'"));

    // Unknown default_profile in config
    let config_bad_default = ConfigFile {
        default_profile: Some("missing".to_string()),
        profiles: config.profiles.clone(),
        ..Default::default()
    };
    let err3 = resolve_packages(&[], None, Some(&config_bad_default)).unwrap_err();
    let err_msg3 = err3.to_string();
    assert!(
        err_msg3.contains("Unknown default profile 'missing'"),
        "got: {}",
        err_msg3
    );
}

#[test]
fn test_end_to_end_profile_filtering() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Create packages: common, git, zsh, work, server
    let packages = ["common", "git", "zsh", "work", "server"];
    for pkg in &packages {
        let pkg_dir = source_dir.path().join(pkg);
        fs::create_dir_all(&pkg_dir).unwrap();
        fs::write(
            pkg_dir.join(format!(".{}_file", pkg)),
            format!("content of {}", pkg),
        )
        .unwrap();
    }

    let mut profiles = BTreeMap::new();
    profiles.insert(
        "work".to_string(),
        ProfileConfig {
            packages: vec!["common".into(), "git".into(), "work".into()],
        },
    );
    profiles.insert(
        "server".to_string(),
        ProfileConfig {
            packages: vec!["common".into(), "server".into()],
        },
    );

    let config = ConfigFile {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        profiles: Some(profiles),
        ..Default::default()
    };

    let cli_args = CommonArgs {
        profile: Some("work".to_string()),
        ..Default::default()
    };

    let resolved = resolve_common_args(&cli_args, Some(&config))
        .unwrap()
        .to_common_args();
    assert_eq!(resolved.packages, vec!["common", "git", "work"]);
    assert_eq!(
        resolve_profile(cli_args.profile.as_deref(), Some(&config)).as_deref(),
        Some("work")
    );

    let plan = plan_stow(&resolved).unwrap();
    assert_eq!(plan.len(), 3);

    execute_plan(&plan, false, None, false).unwrap();

    assert!(target_dir.path().join(".common_file").exists());
    assert!(target_dir.path().join(".git_file").exists());
    assert!(target_dir.path().join(".work_file").exists());
    assert!(!target_dir.path().join(".zsh_file").exists());
    assert!(!target_dir.path().join(".server_file").exists());
}
