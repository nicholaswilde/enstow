use enstow::cli::CommonArgs;
use enstow::stow::plan_stow;
use std::fs;
use tempfile::tempdir;

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
        source: source_dir.path().to_path_buf(),
        target: target_dir.path().to_path_buf(),
        dry_run: true,
        force: false,
        age_key_file: None,
        packages: Vec::new(),
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
        source: source_dir.path().to_path_buf(),
        target: target_dir.path().to_path_buf(),
        dry_run: true,
        force: false,
        age_key_file: None,
        packages: Vec::new(),
    };

    let plan = plan_stow(&args).unwrap();

    assert_eq!(plan.len(), 1);
    assert_eq!(plan[0].target().file_name().unwrap(), "app.conf");
}
