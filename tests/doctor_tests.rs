use age::secrecy::ExposeSecret;
use age::Recipient;
use clap::Parser;
use enstow::cli::{Cli, Commands, CommonArgs};
use enstow::doctor::{
    run_doctor, run_doctor_staged, run_doctor_tracked, CheckSeverity, DoctorReport,
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

    // Verify target binary can be executed in the current environment
    // (skips cross-compilation runners where child processes cannot run without binfmt_misc)
    match std::process::Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => return,
    }

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

    // 3. Run doctor on failure (should exit non-zero)
    let bad_key = source_dir.path().join("missing_key.txt");
    let fail_output = std::process::Command::new(bin)
        .arg("doctor")
        .arg("--source")
        .arg(source_dir.path())
        .arg("--target")
        .arg(target_dir.path())
        .arg("--age-key-file")
        .arg(&bad_key)
        .output()
        .expect("Failed to execute binary");

    assert!(!fail_output.status.success());
}

#[test]
fn test_doctor_symlink_health_target_not_exist_and_stale() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // 1. Target directory does not exist yet
    let nonexistent_target = target_dir.path().join("does_not_exist");
    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(nonexistent_target),
        ..Default::default()
    };
    let report = run_doctor(&args, None).unwrap();
    assert!(report.healthy);
    assert!(report.checks.iter().any(|c| c.category == "symlink_health"
        && c.message
            .contains("Target destination directory does not exist yet")));

    // 2. Stale symlink: file exists in package, but is excluded by ignore rule
    let pkg_file = source_dir.path().join("my_pkg").join("ignored_now.txt");
    fs::create_dir_all(pkg_file.parent().unwrap()).unwrap();
    fs::write(&pkg_file, "content").unwrap();

    let stale_link = target_dir.path().join("ignored_now.txt");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&pkg_file, &stale_link).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&pkg_file, &stale_link).unwrap();

    let stale_args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        packages: vec!["my_pkg".into()],
        ignore: vec!["ignored_now.txt".into()],
        ..Default::default()
    };
    let stale_report = run_doctor(&stale_args, None).unwrap();
    assert!(stale_report
        .checks
        .iter()
        .any(|c| c.category == "symlink_health"
            && c.severity == CheckSeverity::Warning
            && c.message.contains("Stale symlink")));
}

#[test]
fn test_doctor_secret_permissions_target_not_deployed_and_custom_rule() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();
    let key_path = key_dir.path().join("key.txt");
    let secret_path = source_dir.path().join("secret.age");

    create_test_age_key_and_encrypted_file(&key_path, &secret_path, b"data");

    // Target not deployed yet
    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_path),
        ..Default::default()
    };
    let report = run_doctor(&args, None).unwrap();
    assert!(report.healthy);
    assert!(report
        .checks
        .iter()
        .any(|c| c.category == "secret_permissions"
            && c.message.contains("Secret target not yet deployed")));

    // Deployed with custom permissions rule
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let target_file = target_dir.path().join("secret");
        fs::write(&target_file, "data").unwrap();
        fs::set_permissions(&target_file, fs::Permissions::from_mode(0o640)).unwrap();

        let mut perms = enstow::config::PermissionsConfig::new();
        perms.add_rule("secret".into(), 0o640, None);

        let perms_report = run_doctor(&args, Some(&perms)).unwrap();
        assert!(perms_report
            .checks
            .iter()
            .any(|c| c.category == "secret_permissions"
                && c.severity == CheckSeverity::Ok
                && c.message.contains("0640")));
    }
}

#[test]
fn test_doctor_sops_config_and_secret_checks() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Create a .sops.yaml in source
    let sops_config = source_dir.path().join(".sops.yaml");
    fs::write(&sops_config, "creation_rules: []").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        ..Default::default()
    };

    let report = run_doctor(&args, None).unwrap();
    assert!(report
        .checks
        .iter()
        .any(|c| c.category == "decryption_prerequisites"
            && (c.message.contains(".sops.yaml") || c.message.contains("sops"))));

    // Also test with a .sops.json mock file
    let sops_file = source_dir.path().join("secrets.sops.json");
    fs::write(&sops_file, r#"{"data":"mock"}"#).unwrap();
    let sops_report = run_doctor(&args, None).unwrap();
    assert!(sops_report
        .checks
        .iter()
        .any(|c| c.category == "decryption_prerequisites"));
}

#[test]
fn test_doctor_all_leak_heuristics() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let heuristics = [
        ("rsa.txt", "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."),
        ("dsa.txt", "-----BEGIN DSA PRIVATE KEY-----\nMIIB..."),
        ("ec.txt", "-----BEGIN EC PRIVATE KEY-----\nMHQC..."),
        ("pkcs8.txt", "-----BEGIN PRIVATE KEY-----\nMIIE..."),
        ("pgp.txt", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nmQEN..."),
        ("age.txt", "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQ"),
        (
            "gho.txt",
            "token = 'gho_1234567890abcdefghijklmnopqrstuvwxyz'",
        ),
        ("pat.txt", "token = 'github_pat_11AAAAAAA0123456789'"),
        ("glpat.txt", "token = 'glpat-xxxxxxxxxxxxxxxxxxxx'"),
        ("slack_b.txt", "slack = 'xoxb-1234567890-abcdef'"),
        ("slack_p.txt", "slack = 'xoxp-1234567890-abcdef'"),
        ("slack_a.txt", "slack = 'xoxa-1234567890-abcdef'"),
    ];

    for (name, content) in heuristics {
        let f = source_dir.path().join(name);
        fs::write(&f, content).unwrap();
    }

    // Also create a large file (> 1MB) that would otherwise match to verify it gets skipped
    let large_file = source_dir.path().join("large_ignored.txt");
    let large_buf = vec![b'A'; 1_000_001];
    fs::write(&large_file, large_buf).unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        ..Default::default()
    };

    let report = run_doctor(&args, None).unwrap();
    assert_eq!(report.warnings, heuristics.len());
}

#[test]
fn test_doctor_reports_legacy_folded_directory_symlink() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let pkg_nvim = source_dir.path().join("nvim").join(".config").join("nvim");
    fs::create_dir_all(&pkg_nvim).unwrap();
    fs::write(pkg_nvim.join("init.lua"), "-- init\n").unwrap();

    let target_config = target_dir.path().join(".config");
    fs::create_dir_all(&target_config).unwrap();
    let folded_nvim = target_config.join("nvim");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&pkg_nvim, &folded_nvim).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(&pkg_nvim, &folded_nvim).unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        packages: vec!["nvim".to_string()],
        ..Default::default()
    };

    let report = run_doctor(&args, None).unwrap();
    let folded_warnings: Vec<_> = report
        .checks
        .iter()
        .filter(|c| {
            c.category == "symlink_health"
                && c.severity == CheckSeverity::Warning
                && c.message.contains("folded directory symlink")
        })
        .collect();
    assert_eq!(folded_warnings.len(), 1, "checks: {:?}", report.checks);

    // Must not duplicate as generic stale symlink warning
    let stale_warnings: Vec<_> = report
        .checks
        .iter()
        .filter(|c| c.category == "symlink_health" && c.message.contains("Stale symlink"))
        .collect();
    assert!(stale_warnings.is_empty(), "checks: {:?}", report.checks);
}

#[test]
fn test_cli_parsing_doctor_staged() {
    let cli = Cli::try_parse_from(["enstow", "doctor", "--staged", "--json"]).unwrap();
    match cli.command {
        Some(Commands::Doctor {
            json,
            staged,
            tracked,
            ..
        }) => {
            assert!(json);
            assert!(staged);
            assert!(!tracked);
        }
        other => panic!("Expected Doctor command, got {:?}", other),
    }
}

#[test]
fn test_cli_parsing_doctor_tracked_and_staged_conflict() {
    let cli = Cli::try_parse_from(["enstow", "doctor", "--tracked", "--json"]).unwrap();
    match cli.command {
        Some(Commands::Doctor {
            json,
            staged,
            tracked,
            ..
        }) => {
            assert!(json);
            assert!(!staged);
            assert!(tracked);
        }
        other => panic!("Expected Doctor command, got {:?}", other),
    }

    let conflict = Cli::try_parse_from(["enstow", "doctor", "--staged", "--tracked"]);
    assert!(
        conflict.is_err(),
        "expected --staged and --tracked to conflict"
    );
}

#[test]
fn test_doctor_plaintext_sibling_detected_even_when_enstowignored() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let pkg_dir = source_dir.path().join("bash");
    fs::create_dir_all(&pkg_dir).unwrap();

    let key_file = key_dir.path().join("keys.txt");
    let secret_age = pkg_dir.join(".tokens.age");
    create_test_age_key_and_encrypted_file(&key_file, &secret_age, b"export TOKEN=secret\n");

    // Plaintext sibling ignored by .enstowignore MUST still be caught by doctor
    fs::write(pkg_dir.join(".enstowignore"), ".tokens\n").unwrap();
    let plaintext_sibling = pkg_dir.join(".tokens");
    fs::write(&plaintext_sibling, "export TOKEN=secret\n").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_file.clone()),
        packages: vec!["bash".to_string()],
        ..Default::default()
    };

    let report = run_doctor(&args, None).unwrap();
    assert!(!report.healthy, "expected unhealthy report: {:?}", report);
    assert!(
        report.checks.iter().any(|c| {
            c.category == "secret_guard"
                && c.severity == CheckSeverity::Error
                && c.message.contains(".tokens")
        }),
        "checks: {:?}",
        report.checks
    );

    // Removing the plaintext sibling makes doctor healthy again
    fs::remove_file(&plaintext_sibling).unwrap();
    let clean_report = run_doctor(&args, None).unwrap();
    assert!(
        clean_report.healthy,
        "expected healthy report: {:?}",
        clean_report
    );
}

#[test]
fn test_doctor_warns_when_plaintext_counterpart_not_gitignored() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    // Simulate a git repository root
    fs::create_dir_all(source_dir.path().join(".git")).unwrap();

    let pkg_dir = source_dir.path().join("bash");
    fs::create_dir_all(&pkg_dir).unwrap();
    let key_file = key_dir.path().join("keys.txt");
    let secret_age = pkg_dir.join(".tokens.age");
    create_test_age_key_and_encrypted_file(&key_file, &secret_age, b"export TOKEN=secret\n");

    // Exact .sops.yaml must NOT falsely warn or error against itself
    fs::write(source_dir.path().join(".sops.yaml"), "creation_rules: []\n").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_file.clone()),
        packages: vec!["bash".to_string()],
        ..Default::default()
    };

    // 1. No .gitignore -> warns about unignored plaintext counterpart
    let report = run_doctor(&args, None).unwrap();
    assert!(
        report.checks.iter().any(|c| {
            c.category == "secret_guard"
                && c.severity == CheckSeverity::Warning
                && c.message.contains(".gitignore")
                && c.message.contains(".tokens")
        }),
        "checks: {:?}",
        report.checks
    );
    assert!(
        !report
            .checks
            .iter()
            .any(|c| c.category == "secret_guard" && c.message.contains(".sops.yaml")),
        "exact .sops.yaml must not flag itself: {:?}",
        report.checks
    );

    // 2. Adding .tokens to .gitignore clears the warning
    fs::write(source_dir.path().join(".gitignore"), ".tokens\n").unwrap();
    let clean_report = run_doctor(&args, None).unwrap();
    assert!(
        !clean_report
            .checks
            .iter()
            .any(|c| c.category == "secret_guard" && c.severity != CheckSeverity::Ok),
        "expected no secret_guard warnings/errors: {:?}",
        clean_report.checks
    );
}

#[test]
fn test_doctor_staged_blocks_plaintext_siblings_dotenv_and_leaks() {
    let repo_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let git_init = Command::new("git")
        .arg("init")
        .current_dir(repo_dir.path())
        .output();
    if !matches!(git_init, Ok(ref o) if o.status.success()) {
        eprintln!("Skipping git staged test: git CLI unavailable");
        return;
    }

    let bash_dir = repo_dir.path().join("bash");
    fs::create_dir_all(&bash_dir).unwrap();
    let key_file = key_dir.path().join("keys.txt");
    create_test_age_key_and_encrypted_file(
        &key_file,
        &bash_dir.join(".tokens.age"),
        b"export TOKEN=ok\n",
    );
    fs::write(bash_dir.join(".bashrc"), "export PATH=$HOME/bin:$PATH\n").unwrap();
    fs::write(repo_dir.path().join(".env.example"), "API_KEY=\n").unwrap();

    let git_add = |paths: &[&str]| {
        let out = Command::new("git")
            .arg("add")
            .arg("-f")
            .args(paths)
            .current_dir(repo_dir.path())
            .output()
            .unwrap();
        assert!(out.status.success(), "git add failed: {:?}", out);
    };
    let git_reset = |paths: &[&str]| {
        let out = Command::new("git")
            .args(["rm", "--cached", "-f"])
            .args(paths)
            .current_dir(repo_dir.path())
            .output()
            .unwrap();
        assert!(out.status.success(), "git rm --cached failed: {:?}", out);
    };

    // 1. Clean staged set (regular dotfile, .env.example, encrypted .age) passes
    git_add(&["bash/.bashrc", "bash/.tokens.age", ".env.example"]);
    let clean = run_doctor_staged(repo_dir.path()).unwrap();
    assert!(clean.healthy, "expected clean staged report: {:?}", clean);

    // 2. Staging plaintext counterpart bash/.tokens is blocked
    fs::write(bash_dir.join(".tokens"), "export SECRET=plain\n").unwrap();
    git_add(&["bash/.tokens"]);
    let sibling_report = run_doctor_staged(repo_dir.path()).unwrap();
    assert!(!sibling_report.healthy);
    assert!(sibling_report.checks.iter().any(|c| {
        c.category == "secret_guard"
            && c.severity == CheckSeverity::Error
            && c.message.contains(".tokens")
    }));
    git_reset(&["bash/.tokens"]);
    fs::remove_file(bash_dir.join(".tokens")).unwrap();

    // 3. Staging .env and nested secrets.env is blocked
    fs::write(repo_dir.path().join(".env"), "FOO=bar\n").unwrap();
    fs::write(bash_dir.join("secrets.env"), "BAR=baz\n").unwrap();
    git_add(&[".env", "bash/secrets.env"]);
    let dotenv_report = run_doctor_staged(repo_dir.path()).unwrap();
    assert!(!dotenv_report.healthy);
    assert!(dotenv_report.errors >= 2, "report: {:?}", dotenv_report);
    git_reset(&[".env", "bash/secrets.env"]);
    fs::remove_file(repo_dir.path().join(".env")).unwrap();
    fs::remove_file(bash_dir.join("secrets.env")).unwrap();

    // 4. Staging an unencrypted credential leak is blocked
    fs::write(
        bash_dir.join(".bash_exports"),
        "export GH_TOKEN=ghp_1234567890abcdefghijklmnop\n",
    )
    .unwrap();
    git_add(&["bash/.bash_exports"]);
    let leak_report = run_doctor_staged(repo_dir.path()).unwrap();
    assert!(!leak_report.healthy);
    assert!(leak_report.checks.iter().any(|c| {
        c.category == "leak_scan"
            && c.severity == CheckSeverity::Error
            && c.message.contains("GitHub personal access token")
    }));

    // 5. CLI `enstow doctor --staged` exits non-zero on staged violation and 0 when clean
    let bin = env!("CARGO_BIN_EXE_enstow");
    if matches!(Command::new(bin).arg("--version").output(), Ok(o) if o.status.success()) {
        let fail_out = Command::new(bin)
            .current_dir(repo_dir.path())
            .args(["doctor", "--staged"])
            .output()
            .unwrap();
        assert!(!fail_out.status.success());

        git_reset(&["bash/.bash_exports"]);
        fs::remove_file(bash_dir.join(".bash_exports")).unwrap();

        let ok_out = Command::new(bin)
            .current_dir(repo_dir.path())
            .args(["doctor", "--staged"])
            .output()
            .unwrap();
        assert!(
            ok_out.status.success(),
            "expected clean doctor --staged to exit 0: {}",
            String::from_utf8_lossy(&ok_out.stderr)
        );
    }
}

#[test]
fn test_doctor_symlink_health_detects_depth_6_dangling_and_stale_symlinks() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Depth-6 layout under managed `.gemini` subtree
    let skill_dir = source_dir
        .path()
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("demo-skill");
    let scripts_dir = skill_dir.join("scripts");
    let agents_dir = skill_dir.join("agents");
    fs::create_dir_all(&scripts_dir).unwrap();
    fs::create_dir_all(&agents_dir).unwrap();

    let kept_skill = skill_dir.join("SKILL.md"); // depth 5
    let broken_src = scripts_dir.join("broken.sh"); // depth 6 (will be deleted -> dangling)
    let ignored_src = agents_dir.join("openai.yaml"); // depth 6 (will be ignored -> stale)

    fs::write(&kept_skill, "# demo\n").unwrap();
    fs::write(&broken_src, "#!/bin/sh\n").unwrap();
    fs::write(&ignored_src, "name: demo\n").unwrap();

    let initial_args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        ..Default::default()
    };

    let plan = enstow::stow::plan_stow(&initial_args).unwrap();
    enstow::stow::execute_plan(&plan, false, None, false).unwrap();

    // Delete depth-6 script so its symlink becomes dangling
    fs::remove_file(&broken_src).unwrap();

    // Create a dangling symlink inside an ignored dir (node_modules) inside managed subtree
    let ignored_nm_dir = target_dir
        .path()
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("demo-skill")
        .join("node_modules");
    fs::create_dir_all(&ignored_nm_dir).unwrap();
    let ignored_nm_dangling = ignored_nm_dir.join("broken_in_nm");
    let missing_nm_target = source_dir.path().join("missing_nm_target");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&missing_nm_target, &ignored_nm_dangling).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&missing_nm_target, &ignored_nm_dangling).unwrap();

    // Create an unrelated dangling symlink outside managed target subtrees
    let unrelated_dir = target_dir.path().join("unrelated").join("nested");
    fs::create_dir_all(&unrelated_dir).unwrap();
    let unrelated_dangling = unrelated_dir.join("broken_unrelated");
    let missing_unrelated = target_dir.path().join("nonexistent_unrelated");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&missing_unrelated, &unrelated_dangling).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&missing_unrelated, &unrelated_dangling).unwrap();

    // Run doctor with `openai.yaml` ignored (making its target symlink stale, not dangling)
    let doctor_args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        ignore: vec!["openai.yaml".to_string()],
        ..Default::default()
    };

    let report = run_doctor(&doctor_args, None).unwrap();
    assert!(!report.healthy);

    let canon_target = fs::canonicalize(target_dir.path()).unwrap();
    let target_broken = canon_target
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("demo-skill")
        .join("scripts")
        .join("broken.sh");
    let target_stale = target_dir
        .path()
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("demo-skill")
        .join("agents")
        .join("openai.yaml");
    let target_stale_canon = canon_target
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("demo-skill")
        .join("agents")
        .join("openai.yaml");
    let ignored_nm_dangling_canon = canon_target
        .join(".gemini")
        .join("config")
        .join("skills")
        .join("demo-skill")
        .join("node_modules")
        .join("broken_in_nm");
    let unrelated_dangling_canon = canon_target
        .join("unrelated")
        .join("nested")
        .join("broken_unrelated");

    assert!(
        report.checks.iter().any(|c| {
            c.category == "symlink_health"
                && c.severity == CheckSeverity::Error
                && c.message.contains("Dangling symlink")
                && c.path
                    .as_deref()
                    .map(|p| {
                        enstow::stow::normalize_path(p)
                            == enstow::stow::normalize_path(&target_broken)
                    })
                    .unwrap_or(false)
        }),
        "Expected depth-6 dangling symlink error for {}, checks: {:?}",
        target_broken.display(),
        report.checks
    );

    assert!(
        report.checks.iter().any(|c| {
            c.category == "symlink_health"
                && c.severity == CheckSeverity::Warning
                && c.message.contains("Stale symlink")
                && c.path
                    .as_deref()
                    .map(|p| {
                        let norm = enstow::stow::normalize_path(p);
                        norm == enstow::stow::normalize_path(&target_stale)
                            || norm == enstow::stow::normalize_path(&target_stale_canon)
                    })
                    .unwrap_or(false)
        }),
        "Expected depth-6 stale symlink warning for {}, checks: {:?}",
        target_stale.display(),
        report.checks
    );

    assert!(
        !report.checks.iter().any(|c| {
            c.path
                .as_deref()
                .map(|p| {
                    let norm = enstow::stow::normalize_path(p);
                    norm == enstow::stow::normalize_path(&ignored_nm_dangling)
                        || norm == enstow::stow::normalize_path(&ignored_nm_dangling_canon)
                        || norm == enstow::stow::normalize_path(&unrelated_dangling)
                        || norm == enstow::stow::normalize_path(&unrelated_dangling_canon)
                })
                .unwrap_or(false)
        }),
        "Ignored or unrelated dangling symlinks should not be reported, checks: {:?}",
        report.checks
    );
}

#[test]
fn test_doctor_tracked_non_git_dir_returns_error() {
    let non_git = tempdir().unwrap();
    let err = run_doctor_tracked(non_git.path()).unwrap_err();
    assert!(
        err.to_string().contains("not inside a git repository"),
        "unexpected error: {err}"
    );
}

#[test]
fn test_doctor_tracked_audits_committed_files_keys_counterparts_and_leaks() {
    let repo_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let git_init = Command::new("git")
        .arg("init")
        .current_dir(repo_dir.path())
        .output();
    if !matches!(git_init, Ok(ref o) if o.status.success()) {
        eprintln!("Skipping git tracked test: git CLI unavailable");
        return;
    }

    let git_cmd = |args: &[&str]| {
        let out = Command::new("git")
            .args([
                "-c",
                "user.name=Enstow Test",
                "-c",
                "user.email=test@enstow.local",
                "-c",
                "commit.gpgsign=false",
            ])
            .args(args)
            .current_dir(repo_dir.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "git {:?} failed: stdout={} stderr={}",
            args,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    };

    let bash_dir = repo_dir.path().join("bash");
    let ssh_dir = repo_dir.path().join("ssh");
    let certs_dir = repo_dir.path().join("certs");
    let ignored_dir = repo_dir.path().join("ignored_dir");
    fs::create_dir_all(&bash_dir).unwrap();
    fs::create_dir_all(&ssh_dir).unwrap();
    fs::create_dir_all(&certs_dir).unwrap();
    fs::create_dir_all(&ignored_dir).unwrap();

    let key_file = key_dir.path().join("keys.txt");
    create_test_age_key_and_encrypted_file(
        &key_file,
        &bash_dir.join(".tokens.age"),
        b"export TOKEN=ok\n",
    );
    create_test_age_key_and_encrypted_file(
        &key_file,
        &certs_dir.join("tls.key.age"),
        b"dummy encrypted tls key\n",
    );
    fs::write(bash_dir.join(".bashrc"), "export PATH=$HOME/bin:$PATH\n").unwrap();
    fs::write(repo_dir.path().join(".env.example"), "API_KEY=\n").unwrap();
    fs::write(repo_dir.path().join(".enstowignore"), "ignored_dir/\n").unwrap();
    fs::write(
        ssh_dir.join("id_rsa.pub"),
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC user@host\n",
    )
    .unwrap();
    fs::write(
        ssh_dir.join("id_ed25519.pub"),
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI user@host\n",
    )
    .unwrap();
    fs::write(ignored_dir.join("readme.txt"), "safe tracked note\n").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        "/nonexistent/enstow-tracked-symlink-target",
        ignored_dir.join("dangling.link"),
    )
    .unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(
        "C:\\nonexistent\\enstow-tracked-symlink-target",
        ignored_dir.join("dangling.link"),
    )
    .unwrap();

    // 1. Clean committed repo (including public keys, encrypted keys, .env.example) passes
    git_cmd(&["add", "-A"]);
    git_cmd(&["commit", "-m", "initial clean dotfiles"]);
    let clean = run_doctor_tracked(repo_dir.path()).unwrap();
    assert!(clean.healthy, "expected clean tracked report: {:?}", clean);
    assert!(
        clean.checks.iter().any(|c| {
            c.category == "secret_guard"
                && c.severity == CheckSeverity::Ok
                && c.message.contains("tracked file(s)")
        }),
        "checks: {:?}",
        clean.checks
    );

    // 2. Committed root .env and .enstowignore'd nested .env are flagged (even with empty staging area)
    fs::write(repo_dir.path().join(".env"), "FOO=bar\n").unwrap();
    fs::write(ignored_dir.join("app.env"), "BAR=baz\n").unwrap();
    git_cmd(&["add", "-f", ".env", "ignored_dir/app.env"]);
    git_cmd(&["commit", "-m", "add dotenv files"]);

    // Staged check sees 0 staged files; tracked check catches both committed files
    let staged_empty = run_doctor_staged(repo_dir.path()).unwrap();
    assert!(staged_empty.healthy);
    let dotenv_report = run_doctor_tracked(repo_dir.path()).unwrap();
    assert!(!dotenv_report.healthy);
    assert!(
        dotenv_report.errors >= 2,
        "expected >=2 dotenv errors: {:?}",
        dotenv_report
    );
    git_cmd(&["rm", "-f", ".env", "ignored_dir/app.env"]);
    git_cmd(&["commit", "-m", "remove dotenv files"]);

    // 3. Committed private key filenames (*.key, *.pem, id_rsa, id_ed25519) are flagged
    //    even without PEM headers; .pub and .age counterparts remain allowed
    fs::write(certs_dir.join("server.key"), "not-a-pem-header\n").unwrap();
    fs::write(certs_dir.join("private.pem"), "not-a-pem-header\n").unwrap();
    fs::write(ssh_dir.join("id_rsa"), "not-a-pem-header\n").unwrap();
    fs::write(ssh_dir.join("id_ed25519"), "not-a-pem-header\n").unwrap();
    git_cmd(&[
        "add",
        "-f",
        "certs/server.key",
        "certs/private.pem",
        "ssh/id_rsa",
        "ssh/id_ed25519",
    ]);

    // Shared guard also blocks staged private key filenames
    let staged_keys = run_doctor_staged(repo_dir.path()).unwrap();
    assert!(!staged_keys.healthy, "expected staged key files to fail");
    assert!(
        staged_keys.errors >= 4,
        "expected >=4 staged key errors: {:?}",
        staged_keys
    );

    git_cmd(&["commit", "-m", "add private key filenames"]);
    let key_report = run_doctor_tracked(repo_dir.path()).unwrap();
    assert!(!key_report.healthy);
    assert_eq!(
        key_report.errors, 4,
        "expected exactly 4 private key filename errors (ignoring .pub/.age): {:?}",
        key_report
    );
    for forbidden in ["server.key", "private.pem", "id_rsa", "id_ed25519"] {
        assert!(
            key_report.checks.iter().any(|c| {
                c.category == "secret_guard"
                    && c.severity == CheckSeverity::Error
                    && c.message.contains(forbidden)
            }),
            "missing error for {forbidden}: {:?}",
            key_report.checks
        );
    }
    assert!(
        !key_report
            .checks
            .iter()
            .any(|c| c.message.contains(".pub") || c.message.contains(".age")),
        "public/encrypted keys must not be flagged: {:?}",
        key_report.checks
    );
    git_cmd(&[
        "rm",
        "-f",
        "certs/server.key",
        "certs/private.pem",
        "ssh/id_rsa",
        "ssh/id_ed25519",
    ]);
    git_cmd(&["commit", "-m", "remove private key filenames"]);

    // 4. Committed plaintext counterpart alongside bash/.tokens.age is flagged
    fs::write(bash_dir.join(".tokens"), "export SECRET=plain\n").unwrap();
    git_cmd(&["add", "-f", "bash/.tokens"]);
    git_cmd(&["commit", "-m", "add plaintext counterpart"]);
    let counterpart_report = run_doctor_tracked(repo_dir.path()).unwrap();
    assert!(!counterpart_report.healthy);
    assert!(
        counterpart_report.checks.iter().any(|c| {
            c.category == "secret_guard"
                && c.severity == CheckSeverity::Error
                && c.message.contains(".tokens")
        }),
        "checks: {:?}",
        counterpart_report.checks
    );
    git_cmd(&["rm", "-f", "bash/.tokens"]);
    git_cmd(&["commit", "-m", "remove plaintext counterpart"]);

    // 5. Committed credential leak inside an .enstowignore'd tracked file is flagged
    fs::write(
        ignored_dir.join("notes.txt"),
        "token=ghp_1234567890abcdefghijklmnop\n",
    )
    .unwrap();
    git_cmd(&["add", "-f", "ignored_dir/notes.txt"]);
    git_cmd(&["commit", "-m", "add credential leak"]);
    let leak_report = run_doctor_tracked(repo_dir.path()).unwrap();
    assert!(!leak_report.healthy);
    assert!(
        leak_report.checks.iter().any(|c| {
            c.category == "leak_scan"
                && c.severity == CheckSeverity::Error
                && c.message.contains("GitHub personal access token")
        }),
        "checks: {:?}",
        leak_report.checks
    );

    // 6. CLI `enstow doctor --tracked` and `--json` exit non-zero on findings and 0 when clean
    let bin = env!("CARGO_BIN_EXE_enstow");
    if matches!(Command::new(bin).arg("--version").output(), Ok(o) if o.status.success()) {
        let fail_out = Command::new(bin)
            .current_dir(repo_dir.path())
            .args(["doctor", "--tracked", "--json"])
            .output()
            .unwrap();
        assert!(
            !fail_out.status.success(),
            "expected doctor --tracked to exit non-zero on leak"
        );
        let parsed_fail: serde_json::Value =
            serde_json::from_slice(&fail_out.stdout).expect("valid JSON report");
        assert_eq!(parsed_fail["healthy"], serde_json::json!(false));
        assert!(parsed_fail["errors"].as_u64().unwrap_or(0) >= 1);

        git_cmd(&["rm", "-f", "ignored_dir/notes.txt"]);
        git_cmd(&["commit", "-m", "remove credential leak"]);

        let ok_out = Command::new(bin)
            .current_dir(repo_dir.path())
            .args(["doctor", "--tracked", "--json"])
            .output()
            .unwrap();
        assert!(
            ok_out.status.success(),
            "expected clean doctor --tracked to exit 0: {}",
            String::from_utf8_lossy(&ok_out.stderr)
        );
        let parsed_ok: serde_json::Value =
            serde_json::from_slice(&ok_out.stdout).expect("valid JSON report");
        assert_eq!(parsed_ok["healthy"], serde_json::json!(true));
        assert_eq!(parsed_ok["errors"], serde_json::json!(0));
    }
}
