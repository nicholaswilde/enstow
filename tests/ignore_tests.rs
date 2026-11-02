use enstow::cli::CommonArgs;
use enstow::config::{resolve_common_args, ConfigFile};
use enstow::stow::plan_stow;
use std::fs;
use std::sync::Mutex;
use tempfile::tempdir;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

#[test]
fn test_enstowignore_filters_configured_patterns() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Create dotfiles
    let app_conf = source_dir.path().join("app.conf");
    fs::write(&app_conf, "normal config").unwrap();

    let backup_file = source_dir.path().join("app.conf.bak");
    fs::write(&backup_file, "backup content").unwrap();

    let temp_file = source_dir.path().join("tmp_cache.log");
    fs::write(&temp_file, "temporary cache").unwrap();

    // Create .enstowignore
    let ignore_file = source_dir.path().join(".enstowignore");
    fs::write(&ignore_file, "*.bak\n# A comment\ntmp_*\n").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: true,
        force: false,
        prune: false,
        age_key_file: None,
        packages: Vec::new(),
        ignore: Vec::new(),
        ..Default::default()
    };

    let plan = plan_stow(&args).unwrap();

    // Only app.conf should be planned (.bak, tmp_*, and .enstowignore itself ignored)
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].target().file_name().unwrap(), "app.conf");
}

#[test]
fn test_stow_local_ignore_fallback() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let app_conf = source_dir.path().join("app.conf");
    fs::write(&app_conf, "normal config").unwrap();

    let ignored_file = source_dir.path().join("notes.draft");
    fs::write(&ignored_file, "draft notes").unwrap();

    // Create .stow-local-ignore
    let ignore_file = source_dir.path().join(".stow-local-ignore");
    fs::write(&ignore_file, "*.draft\n").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: true,
        force: false,
        prune: false,
        age_key_file: None,
        packages: Vec::new(),
        ignore: Vec::new(),
        ..Default::default()
    };

    let plan = plan_stow(&args).unwrap();

    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].target().file_name().unwrap(), "app.conf");
}

#[test]
fn test_cli_ignore_flag_filters_files() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let app_conf = source_dir.path().join("app.conf");
    fs::write(&app_conf, "normal config").unwrap();

    let backup_file = source_dir.path().join("app.bak");
    fs::write(&backup_file, "backup").unwrap();

    let temp_file = source_dir.path().join("app.tmp");
    fs::write(&temp_file, "temp").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: true,
        force: false,
        prune: false,
        age_key_file: None,
        packages: Vec::new(),
        ignore: vec!["*.bak".to_string(), "*.tmp".to_string()],
        ..Default::default()
    };

    let plan = plan_stow(&args).unwrap();
    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].target().file_name().unwrap(), "app.conf");
}

#[test]
fn test_enstow_ignore_env_applies_across_all_packages() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let orig_ignore = std::env::var("ENSTOW_IGNORE").ok();
    std::env::set_var("ENSTOW_IGNORE", "*.bak,*.tmp");

    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Package 1: zsh
    let zsh_dir = source_dir.path().join("zsh");
    fs::create_dir_all(&zsh_dir).unwrap();
    fs::write(zsh_dir.join(".zshrc"), "export FOO=1").unwrap();
    fs::write(zsh_dir.join(".zshrc.bak"), "export FOO=0").unwrap();

    // Package 2: git
    let git_dir = source_dir.path().join("git");
    fs::create_dir_all(&git_dir).unwrap();
    fs::write(git_dir.join(".gitconfig"), "[user]\nname = Test").unwrap();
    fs::write(git_dir.join("test.tmp"), "scratch").unwrap();

    let cli_args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: true,
        force: false,
        prune: false,
        age_key_file: None,
        packages: vec!["zsh".to_string(), "git".to_string()],
        ignore: Vec::new(),
        ..Default::default()
    };

    let resolved = resolve_common_args(&cli_args, None).to_common_args();
    let plan = plan_stow(&resolved).unwrap();

    std::env::remove_var("ENSTOW_IGNORE");
    if let Some(v) = orig_ignore {
        std::env::set_var("ENSTOW_IGNORE", v);
    }

    assert_eq!(plan.len(), 2);
    let targets: Vec<String> = plan
        .iter()
        .map(|a| {
            a.target()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        })
        .collect();
    assert!(targets.contains(&".zshrc".to_string()));
    assert!(targets.contains(&".gitconfig".to_string()));
}

#[test]
fn test_ignore_patterns_additive_and_deduplicated() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let orig_ignore = std::env::var("ENSTOW_IGNORE").ok();
    std::env::set_var("ENSTOW_IGNORE", "*.tmp,*.log:*.swp");

    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let config = ConfigFile {
        ignore: Some(vec!["*.swp".to_string(), "*.cache".to_string()]),
        ..Default::default()
    };

    let cli_args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        dry_run: true,
        force: false,
        prune: false,
        age_key_file: None,
        packages: Vec::new(),
        ignore: vec!["*.bak".to_string(), "*.tmp".to_string()],
        ..Default::default()
    };

    let resolved = resolve_common_args(&cli_args, Some(&config));

    std::env::remove_var("ENSTOW_IGNORE");
    if let Some(v) = orig_ignore {
        std::env::set_var("ENSTOW_IGNORE", v);
    }

    assert_eq!(
        resolved.ignore,
        vec![
            "*.bak".to_string(),
            "*.tmp".to_string(),
            "*.log".to_string(),
            "*.swp".to_string(),
            "*.cache".to_string()
        ]
    );
}
