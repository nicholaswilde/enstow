use age::secrecy::ExposeSecret;
use age::Recipient;
use enstow::cli::CommonArgs;
use enstow::diff::{colorize_diff, compute_diff, FileDiff};
use enstow::stow::plan_stow;
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
fn test_diff_synced_files_produce_no_diff() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();
    let key_file = key_dir.path().join("key.txt");

    // 1. Synced regular file (symlink)
    let sync_src = source_dir.path().join("synced.txt");
    fs::write(&sync_src, "line 1\nline 2\n").unwrap();
    let sync_tgt = target_dir.path().join("synced.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&sync_src, &sync_tgt).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&sync_src, &sync_tgt).unwrap();

    // 2. Synced secret file
    let secret_src = source_dir.path().join("app.env.age");
    create_test_age_key_and_encrypted_file(&key_file, &secret_src, b"TOKEN=abc123xyz\n");
    let secret_tgt = target_dir.path().join("app.env");
    fs::write(&secret_tgt, b"TOKEN=abc123xyz\n").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_file.clone()),
        ..Default::default()
    };

    let plan = plan_stow(&args).unwrap();
    let diffs = compute_diff(&plan, Some(&key_file), false).unwrap();

    assert!(diffs.is_empty(), "Synced files should produce no diff");
}

#[test]
fn test_diff_regular_file_drift() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Target has drifted from source
    let file_src = source_dir.path().join("config.toml");
    fs::write(&file_src, "port = 8080\nenv = \"prod\"\n").unwrap();
    let file_tgt = target_dir.path().join("config.toml");
    fs::write(&file_tgt, "port = 9090\nenv = \"prod\"\n").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        ..Default::default()
    };

    let plan = plan_stow(&args).unwrap();
    let diffs = compute_diff(&plan, None, false).unwrap();

    assert_eq!(diffs.len(), 1);
    let d = &diffs[0];
    assert!(!d.is_secret);
    assert!(d.diff.contains("--- "));
    assert!(d.diff.contains("+++ "));
    assert!(d.diff.contains("-port = 8080") || d.diff.contains("-port = 9090"));
    assert!(d.diff.contains("+port = 9090") || d.diff.contains("+port = 8080"));
}

#[test]
fn test_diff_secret_drift_unmasked_and_masked() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();
    let key_file = key_dir.path().join("key.txt");

    let secret_src = source_dir.path().join("secret.env.age");
    create_test_age_key_and_encrypted_file(
        &key_file,
        &secret_src,
        b"SUPER_SECRET_A=111\nSAME=value\n",
    );
    let secret_tgt = target_dir.path().join("secret.env");
    fs::write(&secret_tgt, b"SUPER_SECRET_A=222\nSAME=value\n").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_file.clone()),
        ..Default::default()
    };

    let plan = plan_stow(&args).unwrap();

    // Unmasked diff
    let unmasked_diffs = compute_diff(&plan, Some(&key_file), false).unwrap();
    assert_eq!(unmasked_diffs.len(), 1);
    let d_unmasked = &unmasked_diffs[0];
    assert!(d_unmasked.is_secret);
    assert!(d_unmasked.diff.contains("SUPER_SECRET_A"));

    // Masked diff
    let masked_diffs = compute_diff(&plan, Some(&key_file), true).unwrap();
    assert_eq!(masked_diffs.len(), 1);
    let d_masked = &masked_diffs[0];
    assert!(d_masked.is_secret);
    assert!(!d_masked.diff.contains("SUPER_SECRET_A"));
    assert!(d_masked.diff.contains("[MASKED]"));
}

#[test]
fn test_diff_colorize() {
    let raw_diff = "--- a/file\n+++ b/file\n@@ -1 +1 @@\n-old\n+new\n context\n";
    let colored = colorize_diff(raw_diff);

    assert!(colored.contains("\x1b[1m--- a/file\x1b[0m"));
    assert!(colored.contains("\x1b[1m+++ b/file\x1b[0m"));
    assert!(colored.contains("\x1b[36m@@ -1 +1 @@\x1b[0m"));
    assert!(colored.contains("\x1b[31m-old\x1b[0m"));
    assert!(colored.contains("\x1b[32m+new\x1b[0m"));
}

#[test]
fn test_diff_cli_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_enstow");

    // Verify target binary can be executed in the current environment
    // (skips cross-compilation runners where child processes cannot run without binfmt_misc)
    match Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => {
            eprintln!(
                "Skipping end-to-end binary test: target binary cannot be executed in this environment"
            );
            return;
        }
    }

    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();
    let key_file = key_dir.path().join("key.txt");

    let secret_src = source_dir.path().join("api.env.age");
    create_test_age_key_and_encrypted_file(&key_file, &secret_src, b"KEY=top_secret_val\n");
    let secret_tgt = target_dir.path().join("api.env");
    fs::write(&secret_tgt, b"KEY=local_changed_val\n").unwrap();

    // 1. Text diff masked
    let output = Command::new(bin)
        .arg("diff")
        .arg("--source")
        .arg(source_dir.path())
        .arg("--target")
        .arg(target_dir.path())
        .arg("--age-key-file")
        .arg(&key_file)
        .arg("--mask-secrets")
        .output()
        .expect("failed to execute binary");

    assert!(
        output.status.success(),
        "diff command failed: status: {:?}, stdout: {}, stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[MASKED]"));
    assert!(!stdout.contains("top_secret_val"));

    // 2. JSON diff unmasked
    let output_json = Command::new(bin)
        .arg("diff")
        .arg("--source")
        .arg(source_dir.path())
        .arg("--target")
        .arg(target_dir.path())
        .arg("--age-key-file")
        .arg(&key_file)
        .arg("--json")
        .output()
        .expect("failed to execute binary");

    assert!(
        output_json.status.success(),
        "diff json command failed: status: {:?}, stdout: {}, stderr: {}",
        output_json.status,
        String::from_utf8_lossy(&output_json.stdout),
        String::from_utf8_lossy(&output_json.stderr)
    );
    let stdout_json = String::from_utf8_lossy(&output_json.stdout);
    let parsed: Vec<FileDiff> = serde_json::from_str(&stdout_json).expect("valid JSON diff output");
    assert_eq!(parsed.len(), 1);
    assert!(parsed[0].is_secret);
    assert!(parsed[0].diff.contains("top_secret_val"));
}
