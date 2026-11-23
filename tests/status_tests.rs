use age::secrecy::ExposeSecret;
use age::Recipient;
use clap::Parser;
use enstow::cli::{Cli, Commands, CommonArgs};
use enstow::stow::{
    check_status, plan_stow, EntryStatus, FileAction, FileActionStatus, StatusSummary,
};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
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

#[test]
fn test_status_secret_conflict_missing_and_action_getters() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();
    let key_file = key_dir.path().join("key.txt");

    let secret_src = source_dir.path().join("app.env.age");
    create_test_age_key_and_encrypted_file(&key_file, &secret_src, b"secret");

    // 1. Conflict: secret target is a directory
    let dir_tgt = target_dir.path().join("app.env");
    fs::create_dir_all(&dir_tgt).unwrap();

    let action_dir_conflict = enstow::stow::FileAction::Decrypt {
        source: secret_src.clone(),
        target: dir_tgt.clone(),
    };
    assert_eq!(action_dir_conflict.source(), secret_src.as_path());
    assert_eq!(action_dir_conflict.target(), dir_tgt.as_path());

    let statuses = check_status(&[action_dir_conflict], Some(&key_file)).unwrap();
    assert_eq!(statuses[0].status, EntryStatus::Conflict);

    // 2. Conflict: secret target is a symlink
    fs::remove_dir(&dir_tgt).unwrap();
    let dummy_link_src = source_dir.path().join("dummy.txt");
    fs::write(&dummy_link_src, "dummy").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(&dummy_link_src, &dir_tgt).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&dummy_link_src, &dir_tgt).unwrap();

    let action_symlink_conflict = enstow::stow::FileAction::Decrypt {
        source: secret_src.clone(),
        target: dir_tgt.clone(),
    };
    let statuses = check_status(&[action_symlink_conflict], Some(&key_file)).unwrap();
    assert_eq!(statuses[0].status, EntryStatus::Conflict);

    // 3. Missing secret target
    fs::remove_file(&dir_tgt).unwrap();
    let action_missing = enstow::stow::FileAction::Decrypt {
        source: secret_src.clone(),
        target: dir_tgt.clone(),
    };
    let statuses = check_status(&[action_missing], Some(&key_file)).unwrap();
    assert_eq!(statuses[0].status, EntryStatus::Missing);

    // 4. FileAction::Symlink getters
    let sym_action = enstow::stow::FileAction::Symlink {
        source: dummy_link_src.clone(),
        target: dir_tgt.clone(),
    };
    assert_eq!(sym_action.source(), dummy_link_src.as_path());
    assert_eq!(sym_action.target(), dir_tgt.as_path());
}

#[test]
fn test_cli_parsing_status_check_and_exit_code_alias() {
    let cli = Cli::try_parse_from(["enstow", "status", "--check", "--json"]).unwrap();
    match cli.command {
        Some(Commands::Status { json, check, .. }) => {
            assert!(json);
            assert!(check);
        }
        other => panic!("Expected Status, got {:?}", other),
    }

    let cli_alias = Cli::try_parse_from(["enstow", "status", "--exit-code"]).unwrap();
    match cli_alias.command {
        Some(Commands::Status { json, check, .. }) => {
            assert!(!json);
            assert!(check);
        }
        other => panic!("Expected Status, got {:?}", other),
    }
}

#[test]
fn test_cli_status_check_exit_codes() {
    let bin = env!("CARGO_BIN_EXE_enstow");
    match Command::new(bin).arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => return,
    }

    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    fs::write(source_dir.path().join(".bashrc"), "export OK=1\n").unwrap();
    let key_file = key_dir.path().join("key.txt");
    let secret_src = source_dir.path().join(".tokens.age");
    create_test_age_key_and_encrypted_file(&key_file, &secret_src, b"TOKEN=orig\n");

    let run_status = |extra: &[&str]| {
        Command::new(bin)
            .env_remove("ENSTOW_CONFIG")
            .args([
                "status",
                "-s",
                source_dir.path().to_str().unwrap(),
                "-t",
                target_dir.path().to_str().unwrap(),
                "--age-key-file",
                key_file.to_str().unwrap(),
            ])
            .args(extra)
            .output()
            .unwrap()
    };

    // 1. Missing entries: plain `status` exits 0; `--check` and `--exit-code --json` exit 1
    assert!(run_status(&[]).status.success());
    let missing_check = run_status(&["--check"]);
    assert!(!missing_check.status.success());
    assert!(String::from_utf8_lossy(&missing_check.stdout).contains("MISSING"));

    let missing_json = run_status(&["--exit-code", "--json"]);
    assert!(!missing_json.status.success());
    let parsed: serde_json::Value = serde_json::from_slice(&missing_json.stdout).unwrap();
    assert!(parsed.is_array());

    // 2. Apply all -> `status --check` and `status --check --json` exit 0
    let apply_out = Command::new(bin)
        .env_remove("ENSTOW_CONFIG")
        .args([
            "apply",
            "-s",
            source_dir.path().to_str().unwrap(),
            "-t",
            target_dir.path().to_str().unwrap(),
            "--age-key-file",
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(apply_out.status.success());
    assert!(run_status(&["--check"]).status.success());
    assert!(run_status(&["--check", "--json"]).status.success());

    // 3. Drifted secret (`MODIFIED`) -> `--check` exits 1
    fs::write(target_dir.path().join(".tokens"), "TOKEN=drifted\n").unwrap();
    let drifted = run_status(&["--check"]);
    assert!(!drifted.status.success());
    assert!(String::from_utf8_lossy(&drifted.stdout).contains("MODIFIED"));

    // 4. Unmanaged file conflict (`CONFLICT`) -> `--check` exits 1
    fs::write(target_dir.path().join(".tokens"), "TOKEN=orig\n").unwrap();
    fs::remove_file(target_dir.path().join(".bashrc")).unwrap();
    fs::write(target_dir.path().join(".bashrc"), "unmanaged\n").unwrap();
    let conflict = run_status(&["--check"]);
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stdout).contains("CONFLICT"));
}

#[test]
fn test_cli_parsing_status_changes_only_and_short_alias() {
    let default_cli = Cli::try_parse_from(["enstow", "status"]).unwrap();
    match default_cli.command {
        Some(Commands::Status { changes_only, .. }) => assert!(!changes_only),
        other => panic!("Expected Status, got {:?}", other),
    }

    let long_cli = Cli::try_parse_from(["enstow", "status", "--changes-only"]).unwrap();
    match long_cli.command {
        Some(Commands::Status { changes_only, .. }) => assert!(changes_only),
        other => panic!("Expected Status, got {:?}", other),
    }

    let alias_cli =
        Cli::try_parse_from(["enstow", "status", "--short", "--json", "--check"]).unwrap();
    match alias_cli.command {
        Some(Commands::Status {
            json,
            check,
            changes_only,
            ..
        }) => {
            assert!(json);
            assert!(check);
            assert!(changes_only);
        }
        other => panic!("Expected Status, got {:?}", other),
    }
}

#[test]
fn test_status_summary_counts_and_display() {
    let mk = |name: &str, status: EntryStatus| FileActionStatus {
        action: FileAction::Symlink {
            source: Path::new("src").join(name),
            target: Path::new("tgt").join(name),
        },
        status,
    };

    let mixed = vec![
        mk("a", EntryStatus::Synced),
        mk("b", EntryStatus::Synced),
        mk("c", EntryStatus::Missing),
        mk("d", EntryStatus::Conflict),
        mk("e", EntryStatus::Modified),
        mk("f", EntryStatus::Unverified),
    ];
    let summary = StatusSummary::from_statuses(&mixed);
    assert_eq!(summary.synced, 2);
    assert_eq!(summary.missing, 1);
    assert_eq!(summary.conflict, 1);
    assert_eq!(summary.modified, 1);
    assert_eq!(summary.unverified, 1);
    assert!(!summary.all_synced());
    assert_eq!(
        summary.to_string(),
        "Status summary: 2 synced, 1 missing, 1 conflict, 1 modified, 1 unverified."
    );

    let all_ok = vec![mk("a", EntryStatus::Synced)];
    let ok_summary = StatusSummary::from_statuses(&all_ok);
    assert!(ok_summary.all_synced());
    assert_eq!(
        ok_summary.to_string(),
        "Status summary: 1 synced, 0 missing, 0 conflict, 0 modified, 0 unverified."
    );
}

#[test]
fn test_cli_status_changes_only_summary_json_and_check() {
    let bin = env!("CARGO_BIN_EXE_enstow");
    match Command::new(bin).arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => return,
    }

    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();
    let key_file = key_dir.path().join("key.txt");

    // 1. Synced symlink
    let synced_src = source_dir.path().join(".bashrc");
    fs::write(&synced_src, "export OK=1\n").unwrap();
    let synced_tgt = target_dir.path().join(".bashrc");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&synced_src, &synced_tgt).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&synced_src, &synced_tgt).unwrap();

    // 2. Synced secret
    let secret_src = source_dir.path().join(".tokens.age");
    create_test_age_key_and_encrypted_file(&key_file, &secret_src, b"TOKEN=ok\n");
    fs::write(target_dir.path().join(".tokens"), "TOKEN=ok\n").unwrap();

    // 3. Missing file
    let missing_src = source_dir.path().join(".vimrc");
    fs::write(&missing_src, "set number\n").unwrap();

    // 4. Conflict file
    let conflict_src = source_dir.path().join(".gitconfig");
    fs::write(&conflict_src, "[user]\n").unwrap();
    fs::write(target_dir.path().join(".gitconfig"), "unmanaged\n").unwrap();

    // 5. Modified secret (re-using same key)
    let key_content = fs::read_to_string(&key_file).unwrap();
    let identity: age::x25519::Identity = key_content.trim().parse().unwrap();
    let pubkey = identity.to_public();
    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(b"SECRET=orig\n").unwrap();
    writer.finish().unwrap();
    fs::write(source_dir.path().join(".env_secret.age"), encrypted_buf).unwrap();
    fs::write(target_dir.path().join(".env_secret"), "SECRET=drifted\n").unwrap();

    let run_status = |extra: &[&str]| {
        Command::new(bin)
            .env_remove("ENSTOW_CONFIG")
            .args([
                "status",
                "-s",
                source_dir.path().to_str().unwrap(),
                "-t",
                target_dir.path().to_str().unwrap(),
                "--age-key-file",
                key_file.to_str().unwrap(),
            ])
            .args(extra)
            .output()
            .unwrap()
    };

    let expected_mixed_summary =
        "Status summary: 2 synced, 1 missing, 1 conflict, 1 modified, 0 unverified.";

    // Default status shows all rows + summary footer
    let full = run_status(&[]);
    assert!(full.status.success());
    let full_stdout = String::from_utf8_lossy(&full.stdout);
    assert!(full_stdout.contains("SYNCED"));
    assert!(full_stdout.contains("MISSING"));
    assert!(full_stdout.contains("CONFLICT"));
    assert!(full_stdout.contains("MODIFIED"));
    assert!(full_stdout.contains(expected_mixed_summary));

    // --changes-only and --short hide SYNCED rows while preserving full summary counts
    for flag in ["--changes-only", "--short"] {
        let filtered = run_status(&[flag]);
        assert!(filtered.status.success());
        let stdout = String::from_utf8_lossy(&filtered.stdout);
        assert!(
            !stdout.contains("SYNCED"),
            "SYNCED rows should be hidden with {flag}: {stdout}"
        );
        assert!(stdout.contains("MISSING"));
        assert!(stdout.contains("CONFLICT"));
        assert!(stdout.contains("MODIFIED"));
        assert!(stdout.contains(expected_mixed_summary));
    }

    // --changes-only --json emits clean JSON array excluding synced items (no summary line)
    let json_filtered = run_status(&["--changes-only", "--json"]);
    assert!(json_filtered.status.success());
    let json_stdout = String::from_utf8_lossy(&json_filtered.stdout);
    assert!(!json_stdout.contains("Status summary:"));
    let parsed: serde_json::Value = serde_json::from_str(&json_stdout).expect("valid JSON");
    let arr = parsed.as_array().expect("JSON array");
    assert_eq!(arr.len(), 3, "expected 3 non-synced items, got {:?}", arr);
    assert!(arr.iter().all(|v| v["status"] != "synced"));

    // --changes-only --check exits 1 when any entry is not synced
    let check_fail = run_status(&["--changes-only", "--check"]);
    assert!(!check_fail.status.success());
    let check_fail_stdout = String::from_utf8_lossy(&check_fail.stdout);
    assert!(!check_fail_stdout.contains("SYNCED"));
    assert!(check_fail_stdout.contains(expected_mixed_summary));

    // Sync everything via apply --force
    let apply = Command::new(bin)
        .env_remove("ENSTOW_CONFIG")
        .args([
            "apply",
            "--force",
            "-s",
            source_dir.path().to_str().unwrap(),
            "-t",
            target_dir.path().to_str().unwrap(),
            "--age-key-file",
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(apply.status.success());

    // When everything is synced: --changes-only prints only summary (no leading blank line, no SYNCED rows)
    let all_synced = run_status(&["--changes-only", "--check"]);
    assert!(all_synced.status.success());
    let all_synced_stdout = String::from_utf8_lossy(&all_synced.stdout);
    assert_eq!(
        all_synced_stdout,
        "Status summary: 5 synced, 0 missing, 0 conflict, 0 modified, 0 unverified.\n"
    );

    // When everything is synced: --short --json prints empty JSON array
    let all_synced_json = run_status(&["--short", "--json", "--check"]);
    assert!(all_synced_json.status.success());
    let parsed_empty: serde_json::Value =
        serde_json::from_slice(&all_synced_json.stdout).expect("valid JSON");
    assert_eq!(parsed_empty, serde_json::json!([]));
}
