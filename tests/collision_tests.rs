use enstow::cli::CommonArgs;
use enstow::error::EnstowError;
use enstow::stow::{execute_plan, plan_stow, FileAction};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_skip_existing_identical_symlink() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let file = source_dir.path().join("dot.bashrc");
    fs::write(&file, "alias ll='ls -la'").unwrap();

    let target_link = target_dir.path().join("dot.bashrc");

    // Pre-create identical symlink
    #[cfg(unix)]
    std::os::unix::fs::symlink(&file, &target_link).unwrap();

    let args = CommonArgs {
        source: source_dir.path().to_path_buf(),
        target: target_dir.path().to_path_buf(),
        dry_run: false,
        age_key_file: None,
        force: false,
    };

    let actions = plan_stow(&args).unwrap();
    // Should execute cleanly without error
    execute_plan(&actions, false, None, false).unwrap();
}

#[test]
fn test_collision_with_existing_file_fails_without_force() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let file = source_dir.path().join("app.conf");
    fs::write(&file, "new config").unwrap();

    let existing_target = target_dir.path().join("app.conf");
    fs::write(&existing_target, "existing unmanaged file").unwrap();

    let actions = vec![FileAction::Symlink {
        source: file.clone(),
        target: existing_target.clone(),
    }];

    // Without force, should return Collision error
    let res = execute_plan(&actions, false, None, false);
    match res {
        Err(EnstowError::Collision { path }) => {
            assert_eq!(path, existing_target);
        }
        other => panic!("Expected Collision error, got {:?}", other),
    }

    // Verify existing file is preserved
    assert_eq!(
        fs::read_to_string(&existing_target).unwrap(),
        "existing unmanaged file"
    );
}

#[test]
fn test_collision_overwritten_with_force() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let file = source_dir.path().join("app.conf");
    fs::write(&file, "new config").unwrap();

    let existing_target = target_dir.path().join("app.conf");
    fs::write(&existing_target, "existing unmanaged file").unwrap();

    let actions = vec![FileAction::Symlink {
        source: file.clone(),
        target: existing_target.clone(),
    }];

    // With force=true, should succeed and overwrite/replace target
    execute_plan(&actions, false, None, true).unwrap();

    #[cfg(unix)]
    {
        assert!(fs::symlink_metadata(&existing_target)
            .unwrap()
            .file_type()
            .is_symlink());
        let points_to = fs::read_link(&existing_target).unwrap();
        assert_eq!(points_to, file);
    }
}
