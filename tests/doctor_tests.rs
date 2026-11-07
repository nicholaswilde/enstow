use age::secrecy::ExposeSecret;
use age::Recipient;
use enstow::cli::CommonArgs;
use enstow::doctor::{run_doctor, CheckSeverity, DoctorReport};
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
fn test_doctor_clean_repo_is_healthy() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let file_a = source_dir.path().join("dot_bashrc");
    fs::write(&file_a, "export FOO=bar").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        ..Default::default()
    };

    let report = run_doctor(&args, None).unwrap();
    assert!(report.healthy);
    assert_eq!(report.errors, 0);
}

#[test]
fn test_doctor_package_collision_detection() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Package 1
    let pkg1 = source_dir.path().join("pkg1");
    fs::create_dir_all(&pkg1).unwrap();
    fs::write(pkg1.join("config.toml"), "pkg1_data").unwrap();

    // Package 2
    let pkg2 = source_dir.path().join("pkg2");
    fs::create_dir_all(&pkg2).unwrap();
    fs::write(pkg2.join("config.toml"), "pkg2_data").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        packages: vec!["pkg1".into(), "pkg2".into()],
        ..Default::default()
    };

    let report = run_doctor(&args, None).unwrap();
    assert!(!report.healthy);
    assert!(report.errors > 0);
    assert!(report
        .checks
        .iter()
        .any(|c| c.category == "package_collisions"
            && c.severity == CheckSeverity::Error
            && c.message.contains("config.toml")));
}

#[test]
fn test_doctor_symlink_health_dangling() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Create a dangling symlink in target pointing into source_dir
    let dangling_target = target_dir.path().join("broken_link");
    let nonexistent_source = source_dir.path().join("deleted_file.txt");

    #[cfg(unix)]
    std::os::unix::fs::symlink(&nonexistent_source, &dangling_target).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&nonexistent_source, &dangling_target).unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        ..Default::default()
    };

    let report = run_doctor(&args, None).unwrap();
    assert!(!report.healthy);
    assert!(report.checks.iter().any(|c| c.category == "symlink_health"
        && c.severity == CheckSeverity::Error
        && c.message.contains("Dangling symlink")));
}

#[test]
#[cfg(unix)]
fn test_doctor_secret_permissions_check() {
    use std::os::unix::fs::PermissionsExt;

    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();
    let key_path = key_dir.path().join("key.txt");
    let secret_path = source_dir.path().join("secret.age");

    create_test_age_key_and_encrypted_file(&key_path, &secret_path, b"super_secret");

    // Create target file with insecure mode 0644
    let target_file = target_dir.path().join("secret");
    fs::write(&target_file, "super_secret").unwrap();
    fs::set_permissions(&target_file, fs::Permissions::from_mode(0o644)).unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_path),
        ..Default::default()
    };

    let report = run_doctor(&args, None).unwrap();
    assert!(!report.healthy);
    assert!(report
        .checks
        .iter()
        .any(|c| c.category == "secret_permissions"
            && c.severity == CheckSeverity::Error
            && c.message.contains("0644")));

    // Now fix permissions to 0600
    fs::set_permissions(&target_file, fs::Permissions::from_mode(0o600)).unwrap();
    let fixed_report = run_doctor(&args, None).unwrap();
    assert!(fixed_report
        .checks
        .iter()
        .any(|c| c.category == "secret_permissions"
            && c.severity == CheckSeverity::Ok
            && c.message.contains("0600")));
}

#[test]
fn test_doctor_decryption_prerequisites_check() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();
    let key_path = key_dir.path().join("key.txt");
    let secret_path = source_dir.path().join("passwords.age");

    create_test_age_key_and_encrypted_file(&key_path, &secret_path, b"pass123");

    // Pass invalid key file path
    let bad_key_path = key_dir.path().join("nonexistent_key.txt");
    let bad_args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(bad_key_path),
        ..Default::default()
    };

    let report = run_doctor(&bad_args, None).unwrap();
    assert!(!report.healthy);
    assert!(report
        .checks
        .iter()
        .any(|c| c.category == "decryption_prerequisites" && c.severity == CheckSeverity::Error));

    // Pass valid key file path
    let good_args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_path),
        ..Default::default()
    };

    let good_report = run_doctor(&good_args, None).unwrap();
    assert!(good_report.healthy);
    assert!(good_report
        .checks
        .iter()
        .any(|c| c.category == "decryption_prerequisites" && c.severity == CheckSeverity::Ok));
}

#[test]
fn test_doctor_leak_scan_heuristics() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Plaintext dotfile with an exposed private key header
    let leak_file = source_dir.path().join("id_rsa_leaked");
    fs::write(
        &leak_file,
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        ..Default::default()
    };

    let report = run_doctor(&args, None).unwrap();
    assert!(report.warnings > 0);
    assert!(report.checks.iter().any(|c| c.category == "leak_scan"
        && c.severity == CheckSeverity::Warning
        && c.message.contains("credential leak")));
}

#[test]
fn test_doctor_cli_binary_execution() {
    let bin = env!("CARGO_BIN_EXE_enstow");
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let file_a = source_dir.path().join(".bashrc");
    fs::write(&file_a, "echo hello").unwrap();

    // 1. Run doctor --json
    let output = std::process::Command::new(bin)
        .arg("doctor")
        .arg("--source")
        .arg(source_dir.path())
        .arg("--target")
        .arg(target_dir.path())
        .arg("--json")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let json_report: DoctorReport =
        serde_json::from_str(&stdout).expect("Failed to parse JSON report");
    assert!(json_report.healthy);
    assert_eq!(json_report.errors, 0);

    // 2. Run lint alias
    let lint_output = std::process::Command::new(bin)
        .arg("lint")
        .arg("--source")
        .arg(source_dir.path())
        .arg("--target")
        .arg(target_dir.path())
        .output()
        .expect("Failed to execute binary");

    assert!(lint_output.status.success());
    let lint_stdout = String::from_utf8(lint_output.stdout).unwrap();
    assert!(lint_stdout.contains("Doctor summary:"));
}
