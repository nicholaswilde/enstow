use age::secrecy::ExposeSecret;
use age::Recipient;
use enstow::cli::CommonArgs;
use enstow::stow::{check_status, plan_stow, EntryStatus};
use std::fs;
use std::io::Write;
use std::path::Path;
use tempfile::tempdir;

fn create_test_age_key_and_encrypted_file(key_path: &Path, secret_path: &Path, plaintext: &[u8]) {
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(key_path, key.to_string().expose_secret()).unwrap();

    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    fs::write(secret_path, encrypted_buf).unwrap();
}

#[test]
fn test_status_classification() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();
    let key_file = key_dir.path().join("key.txt");

    // 1. Synced file (proper symlink)
    let sync_src = source_dir.path().join("synced.txt");
    fs::write(&sync_src, "synced").unwrap();
    let sync_tgt = target_dir.path().join("synced.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&sync_src, &sync_tgt).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&sync_src, &sync_tgt).unwrap();

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
    create_test_age_key_and_encrypted_file(&key_file, &secret_src, b"decrypted");
    let secret_tgt = target_dir.path().join("app.env");
    fs::write(&secret_tgt, "decrypted").unwrap();

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

    let plan = plan_stow(&args).unwrap();
    let statuses = check_status(&plan, Some(&key_file)).unwrap();

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

#[test]
fn test_secret_status_drift_detection_and_missing_keys() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();
    let key_file = key_dir.path().join("key.txt");

    // 1. Synced secret: decrypted content matches target content
    let synced_src = source_dir.path().join("synced.env.age");
    create_test_age_key_and_encrypted_file(&key_file, &synced_src, b"secret_sync_content");
    let synced_tgt = target_dir.path().join("synced.env");
    fs::write(&synced_tgt, b"secret_sync_content").unwrap();

    // 2. Drifted / Modified secret: decrypted content differs from target
    let drifted_src = source_dir.path().join("drifted.env.age");
    // Encrypt with same key
    let key_content = fs::read_to_string(&key_file).unwrap();
    let identity: age::x25519::Identity = key_content.trim().parse().unwrap();
    let pubkey = identity.to_public();
    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(b"original_encrypted_content").unwrap();
    writer.finish().unwrap();
    fs::write(&drifted_src, encrypted_buf).unwrap();

    let drifted_tgt = target_dir.path().join("drifted.env");
    fs::write(&drifted_tgt, b"modified_local_content").unwrap();

    // 3. Plan stow
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

    let plan = plan_stow(&args).unwrap();
    assert_eq!(plan.len(), 2);

    // Verify with keys available: drifted is Modified, synced is Synced
    let verified_statuses = check_status(&plan, Some(&key_file)).unwrap();
    let get_verified_status = |name: &str| -> EntryStatus {
        verified_statuses
            .iter()
            .find(|s| s.action.target().file_name().unwrap() == name)
            .unwrap()
            .status
    };
    assert_eq!(get_verified_status("synced.env"), EntryStatus::Synced);
    assert_eq!(get_verified_status("drifted.env"), EntryStatus::Modified);

    // Verify JSON serialization includes "modified"
    let json_output = serde_json::to_string(&verified_statuses).unwrap();
    assert!(json_output.contains("\"status\":\"synced\""));
    assert!(json_output.contains("\"status\":\"modified\""));

    // Verify without keys available: both become Unverified gracefully (no crash/error)
    let missing_key_file = key_dir.path().join("non_existent_key.txt");
    let unverified_statuses = check_status(&plan, Some(&missing_key_file)).unwrap();
    let get_unverified_status = |name: &str| -> EntryStatus {
        unverified_statuses
            .iter()
            .find(|s| s.action.target().file_name().unwrap() == name)
            .unwrap()
            .status
    };
    assert_eq!(get_unverified_status("synced.env"), EntryStatus::Unverified);
    assert_eq!(
        get_unverified_status("drifted.env"),
        EntryStatus::Unverified
    );

    let unverified_json = serde_json::to_string(&unverified_statuses).unwrap();
    assert!(unverified_json.contains("\"status\":\"unverified\""));
}
