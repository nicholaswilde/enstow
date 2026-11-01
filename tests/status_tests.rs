use enstow::cli::CommonArgs;
use enstow::stow::{check_status, plan_stow, EntryStatus};
use std::fs;
use tempfile::tempdir;

#[test]
fn test_status_classification() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // 1. Synced file (proper symlink)
    let sync_src = source_dir.path().join("synced.txt");
    fs::write(&sync_src, "synced").unwrap();
    let sync_tgt = target_dir.path().join("synced.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&sync_src, &sync_tgt).unwrap();

    // 2. Missing file (in source, but target absent)
    let missing_src = source_dir.path().join("missing.txt");
    fs::write(&missing_src, "missing").unwrap();

    // 3. Conflict file (unmanaged file in target)
    let conflict_src = source_dir.path().join("conflict.txt");
    fs::write(&conflict_src, "source content").unwrap();
    let conflict_tgt = target_dir.path().join("conflict.txt");
    fs::write(&conflict_tgt, "target conflicting content").unwrap();

    // 4. Secret file (synced plaintext)
    let secret_src = source_dir.path().join("app.env.age");
    fs::write(&secret_src, "age payload").unwrap();
    let secret_tgt = target_dir.path().join("app.env");
    fs::write(&secret_tgt, "decrypted").unwrap();

    let args = CommonArgs {
        source: source_dir.path().to_path_buf(),
        target: target_dir.path().to_path_buf(),
        dry_run: false,
        force: false,
        age_key_file: None,
    };

    let plan = plan_stow(&args).unwrap();
    let statuses = check_status(&plan).unwrap();

    assert_eq!(statuses.len(), 4);

    let get_status = |name: &str| -> EntryStatus {
        statuses
            .iter()
            .find(|s| s.action.target().file_name().unwrap() == name)
            .unwrap()
            .status
    };

    assert_eq!(get_status("synced.txt"), EntryStatus::Synced);
    assert_eq!(get_status("missing.txt"), EntryStatus::Missing);
    assert_eq!(get_status("conflict.txt"), EntryStatus::Conflict);
    assert_eq!(get_status("app.env"), EntryStatus::Synced);
}
