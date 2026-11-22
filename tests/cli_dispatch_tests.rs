use age::secrecy::ExposeSecret;
use age::Recipient;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

fn compile_mock_editor(dir: &Path, content: Option<&str>, exit_code: i32) -> std::path::PathBuf {
    let source_path = dir.join("mock_editor_src.rs");
    let bin_path = dir.join(if cfg!(windows) {
        "mock_editor.exe"
    } else {
        "mock_editor"
    });
    let code = match content {
        Some(text) => format!(
            "fn main() {{ let p = std::env::args().last().unwrap(); std::fs::write(p, {:?}).unwrap(); std::process::exit({}); }}",
            text, exit_code
        ),
        None => format!("fn main() {{ std::process::exit({}); }}", exit_code),
    };
    fs::write(&source_path, code).unwrap();
    let status = Command::new("rustc")
        .arg(&source_path)
        .arg("-o")
        .arg(&bin_path)
        .status()
        .expect("Failed to invoke rustc");
    assert!(status.success(), "Failed to compile mock editor");
    bin_path
}

#[test]
fn test_cli_subcommands_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_enstow");

    // Skip in environments that cannot run host binaries
    match Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => {
            eprintln!("Skipping end-to-end binary test: target binary cannot be executed");
            return;
        }
    }

    let src = tempdir().unwrap();
    let tgt = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    // 1. Setup age key
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    let key_file = key_dir.path().join("key.txt");
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    // Create dotfiles in src for status coverage
    let bashrc = src.path().join(".bashrc");
    fs::write(&bashrc, "export FOO=bar\n").unwrap();

    let secret_src = src.path().join("secret.env.age");
    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(b"KEY=val\n").unwrap();
    writer.finish().unwrap();
    fs::write(&secret_src, encrypted_buf).unwrap();

    // 1b. Additional files for full status classification (MISSING, CONFLICT, MODIFIED, UNVERIFIED)
    let missing_src = src.path().join("missing.txt");
    fs::write(&missing_src, "missing").unwrap();

    let conflict_src = src.path().join("conflict.txt");
    fs::write(&conflict_src, "conflict").unwrap();
    fs::write(tgt.path().join("conflict.txt"), "unmanaged file").unwrap();

    let modified_src = src.path().join("modified.env.age");
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(b"KEY=orig\n").unwrap();
    writer.finish().unwrap();
    fs::write(&modified_src, encrypted_buf).unwrap();
    fs::write(tgt.path().join("modified.env"), "KEY=changed_locally\n").unwrap();

    let unverified_src = src.path().join("unverified.env.age");
    let other_key = age::x25519::Identity::generate();
    let other_pub = other_key.to_public();
    let other_recip: &dyn Recipient = &other_pub;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(other_recip)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(b"KEY=unverified\n").unwrap();
    writer.finish().unwrap();
    fs::write(&unverified_src, encrypted_buf).unwrap();
    fs::write(tgt.path().join("unverified.env"), "KEY=any\n").unwrap();

    // Setup .bashrc and secret.env in tgt as synced
    #[cfg(unix)]
    std::os::unix::fs::symlink(&bashrc, tgt.path().join(".bashrc")).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(&bashrc, tgt.path().join(".bashrc")).unwrap();
    fs::write(tgt.path().join("secret.env"), "KEY=val\n").unwrap();

    // Subcommand: Status (text output: covers SYNCED, MISSING, CONFLICT, MODIFIED, UNVERIFIED)
    let output = Command::new(bin)
        .args([
            "status",
            "-s",
            src.path().to_str().unwrap(),
            "-t",
            tgt.path().to_str().unwrap(),
            "--age-key-file",
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SYNCED"));
    assert!(stdout.contains("MISSING"));
    assert!(stdout.contains("CONFLICT"));
    assert!(stdout.contains("MODIFIED"));
    assert!(stdout.contains("UNVERIFIED"));

    // Subcommand: Status (json output)
    let output = Command::new(bin)
        .args([
            "status",
            "--json",
            "-s",
            src.path().to_str().unwrap(),
            "-t",
            tgt.path().to_str().unwrap(),
            "--age-key-file",
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"status\": \"synced\""));

    // Clean up temporary status test files before running apply
    fs::remove_file(&missing_src).unwrap();
    fs::remove_file(&conflict_src).unwrap();
    fs::remove_file(tgt.path().join("conflict.txt")).unwrap();
    fs::remove_file(&modified_src).unwrap();
    fs::remove_file(tgt.path().join("modified.env")).unwrap();
    fs::remove_file(&unverified_src).unwrap();
    fs::remove_file(tgt.path().join("unverified.env")).unwrap();

    // Subcommand: Apply with --force and --prune
    let output = Command::new(bin)
        .args([
            "apply",
            "--force",
            "--prune",
            "-s",
            src.path().to_str().unwrap(),
            "-t",
            tgt.path().to_str().unwrap(),
            "--age-key-file",
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "apply failed: {:?}", output);
    assert!(tgt.path().join(".bashrc").exists());
    assert!(tgt.path().join("secret.env").exists());

    // Subcommand: Diff
    let output = Command::new(bin)
        .args([
            "diff",
            "-s",
            src.path().to_str().unwrap(),
            "-t",
            tgt.path().to_str().unwrap(),
            "--age-key-file",
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "diff failed: {:?}", output);

    // Subcommand: Restow
    let output = Command::new(bin)
        .args([
            "restow",
            "-s",
            src.path().to_str().unwrap(),
            "-t",
            tgt.path().to_str().unwrap(),
            "--age-key-file",
            key_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "restow failed: {:?}", output);

    // Subcommand: Unstow
    let output = Command::new(bin)
        .args([
            "unstow",
            "-s",
            src.path().to_str().unwrap(),
            "-t",
            tgt.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "unstow failed: {:?}", output);
    assert!(!tgt.path().join(".bashrc").exists());
    assert!(!tgt.path().join("secret.env").exists());

    // Subcommand: Encrypt with explicit -o
    let plain_to_encrypt = src.path().join("plain.txt");
    fs::write(&plain_to_encrypt, "supersecret\n").unwrap();
    let encrypted_out = src.path().join("plain.txt.age");

    let output = Command::new(bin)
        .args([
            "encrypt",
            plain_to_encrypt.to_str().unwrap(),
            "-o",
            encrypted_out.to_str().unwrap(),
            "--recipient",
            &pubkey.to_string(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "encrypt failed: {:?}", output);
    assert!(encrypted_out.exists());

    // Subcommand: Encrypt without -o (default output path)
    let auto_plain = src.path().join("auto.txt");
    fs::write(&auto_plain, "auto\n").unwrap();
    let output = Command::new(bin)
        .args([
            "encrypt",
            auto_plain.to_str().unwrap(),
            "--recipient",
            &pubkey.to_string(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(src.path().join("auto.txt.age").exists());

    // Subcommand: Encrypt with --passphrase
    let pass_plain = src.path().join("pass_plain.txt");
    fs::write(&pass_plain, "passphrase_secret_payload\n").unwrap();
    let pass_encrypted_out = src.path().join("pass_plain.txt.age");

    let output = Command::new(bin)
        .args([
            "encrypt",
            pass_plain.to_str().unwrap(),
            "-o",
            pass_encrypted_out.to_str().unwrap(),
            "--passphrase",
        ])
        .env("ENSTOW_PASSPHRASE", "test-pass-cli-456")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "encrypt --passphrase failed: {:?}",
        output
    );
    assert!(pass_encrypted_out.exists());

    // Subcommand: Decrypt with output file
    let pass_decrypted_out = src.path().join("pass_decrypted.txt");
    let output = Command::new(bin)
        .args([
            "decrypt",
            pass_encrypted_out.to_str().unwrap(),
            "-o",
            pass_decrypted_out.to_str().unwrap(),
        ])
        .env("ENSTOW_PASSPHRASE", "test-pass-cli-456")
        .output()
        .unwrap();
    assert!(output.status.success(), "decrypt failed: {:?}", output);
    assert_eq!(
        fs::read_to_string(&pass_decrypted_out).unwrap(),
        "passphrase_secret_payload\n"
    );

    // Subcommand: Decrypt to stdout
    let output = Command::new(bin)
        .args(["decrypt", pass_encrypted_out.to_str().unwrap()])
        .env("ENSTOW_PASSPHRASE", "test-pass-cli-456")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "decrypt to stdout failed: {:?}",
        output
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "passphrase_secret_payload\n"
    );

    // Subcommand: Sync alias for Apply
    let output = Command::new(bin)
        .args([
            "sync",
            "-n",
            "-s",
            src.path().to_str().unwrap(),
            "-t",
            tgt.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "sync command failed: {:?}", output);

    // Subcommand: Edit (modifying)
    let editor_bin = compile_mock_editor(src.path(), Some("EDITED_CONTENT\n"), 0);
    let output = Command::new(bin)
        .args([
            "edit",
            encrypted_out.to_str().unwrap(),
            "--age-key-file",
            key_file.to_str().unwrap(),
            "--editor",
            editor_bin.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "edit failed: {:?}", output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Saved and re-encrypted"));

    // Subcommand: Edit (unchanged)
    let noop_editor = compile_mock_editor(src.path(), None, 0);
    let output = Command::new(bin)
        .args([
            "edit",
            encrypted_out.to_str().unwrap(),
            "--age-key-file",
            key_file.to_str().unwrap(),
            "--editor",
            noop_editor.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No changes made"));

    // Subcommand: Man
    let output = Command::new(bin).arg("man").output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(".TH enstow 1"));

    // Subcommand: Completions (dynamic)
    let output = Command::new(bin)
        .args(["completions", "bash"])
        .output()
        .unwrap();
    assert!(output.status.success());

    // Subcommand: Completions (static)
    let output = Command::new(bin)
        .args(["completions", "bash", "--static"])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn test_cli_parsing_passphrase_and_decrypt() {
    use clap::Parser;
    use enstow::cli::{Cli, Commands};

    // Encrypt with passphrase
    let cli = Cli::try_parse_from(["enstow", "encrypt", "-p", "file.txt"]).unwrap();
    match cli.command {
        Some(Commands::Encrypt { passphrase, .. }) => assert!(passphrase),
        other => panic!("Expected Encrypt, got {:?}", other),
    }

    // Encrypt with passphrase and recipient should conflict
    let err =
        Cli::try_parse_from(["enstow", "encrypt", "-p", "-r", "age1xxx", "file.txt"]).unwrap_err();
    assert!(err.to_string().contains("cannot be used with"));

    // Decrypt command
    let cli = Cli::try_parse_from(["enstow", "decrypt", "file.txt.age", "-o", "file.txt"]).unwrap();
    match cli.command {
        Some(Commands::Decrypt { file, output, .. }) => {
            assert_eq!(file, std::path::PathBuf::from("file.txt.age"));
            assert_eq!(output, Some(std::path::PathBuf::from("file.txt")));
        }
        other => panic!("Expected Decrypt, got {:?}", other),
    }

    // Sync alias
    let cli = Cli::try_parse_from(["enstow", "sync"]).unwrap();
    match cli.command {
        Some(Commands::Apply(_)) => {}
        other => panic!("Expected Apply via sync alias, got {:?}", other),
    }
}

#[test]
fn test_cli_repo_local_auto_discovery_and_cross_dir_config() {
    let bin = env!("CARGO_BIN_EXE_enstow");

    // Skip in cross-compiled environments that cannot run host binaries
    match Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => {
            eprintln!("Skipping CLI repo-local config test: target binary cannot be executed");
            return;
        }
    }

    let workspace = tempdir().unwrap();
    let repo = workspace.path().join("dotfiles");
    let other_cwd = workspace.path().join("other");
    let xdg_dir = workspace.path().join("xdg");
    let tgt1 = workspace.path().join("tgt1");
    let tgt2 = workspace.path().join("tgt2");
    let tgt3 = workspace.path().join("tgt3");

    fs::create_dir_all(repo.join("bash")).unwrap();
    fs::create_dir_all(repo.join("extra")).unwrap();
    fs::create_dir_all(&other_cwd).unwrap();
    fs::create_dir_all(xdg_dir.join("enstow")).unwrap();
    fs::create_dir_all(&tgt1).unwrap();
    fs::create_dir_all(&tgt2).unwrap();
    fs::create_dir_all(&tgt3).unwrap();

    fs::write(repo.join("bash").join(".bashrc"), "export LOCAL=1\n").unwrap();
    fs::write(repo.join("extra").join(".extrarc"), "export EXTRA=1\n").unwrap();
    fs::write(
        repo.join(".enstow.toml"),
        "source = \".\"\npackages = [\"bash\"]\n",
    )
    .unwrap();
    // Competing global config that selects `extra` instead of `bash`
    fs::write(
        xdg_dir.join("enstow").join("config.toml"),
        "packages = [\"extra\"]\n",
    )
    .unwrap();

    // 1. Inside repo dir with no -C or -s: auto-discovers .enstow.toml over global config
    let output = Command::new(bin)
        .current_dir(&repo)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_SOURCE")
        .args(["apply", "-t", tgt1.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "apply in repo dir failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fs::symlink_metadata(tgt1.join(".bashrc")).is_ok());
    assert!(fs::symlink_metadata(tgt1.join(".extrarc")).is_err());

    // 2. Outside repo dir with -C <repo>/.enstow.toml and NO -s: resolves source="." relative to config
    let output = Command::new(bin)
        .current_dir(&other_cwd)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_SOURCE")
        .args([
            "-C",
            repo.join(".enstow.toml").to_str().unwrap(),
            "status",
            "-t",
            tgt1.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "cross-dir status with -C failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SYNCED"), "expected SYNCED in:\n{stdout}");
    assert!(stdout.contains(".bashrc"), "expected .bashrc in:\n{stdout}");
    assert!(
        !stdout.contains(".extrarc"),
        "unexpected .extrarc in:\n{stdout}"
    );

    // 3. Outside repo dir with top-level -s <repo> and NO -C: auto-discovers <repo>/.enstow.toml
    let output = Command::new(bin)
        .current_dir(&other_cwd)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_SOURCE")
        .args(["-s", repo.to_str().unwrap(), "-t", tgt2.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "top-level -s apply failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fs::symlink_metadata(tgt2.join(".bashrc")).is_ok());
    assert!(fs::symlink_metadata(tgt2.join(".extrarc")).is_err());

    // 4. Outside repo dir with subcommand `apply -s <repo>` and NO -C: auto-discovers <repo>/.enstow.toml
    let output = Command::new(bin)
        .current_dir(&other_cwd)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_SOURCE")
        .args([
            "apply",
            "-s",
            repo.to_str().unwrap(),
            "-t",
            tgt3.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "subcommand apply -s failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fs::symlink_metadata(tgt3.join(".bashrc")).is_ok());
    assert!(fs::symlink_metadata(tgt3.join(".extrarc")).is_err());
}

#[test]
fn test_cli_timestamped_backup_runs_and_summary() {
    let bin = env!("CARGO_BIN_EXE_enstow");

    match Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => {
            eprintln!("Skipping CLI backup test: target binary cannot be executed");
            return;
        }
    }

    let temp = tempdir().unwrap();
    let xdg_dir = temp.path().join("xdg");
    let src = temp.path().join("src");
    let tgt = temp.path().join("tgt");
    fs::create_dir_all(&xdg_dir).unwrap();
    fs::create_dir_all(&src).unwrap();
    fs::create_dir_all(&tgt).unwrap();

    fs::write(src.join("app.conf"), "managed_app\n").unwrap();
    fs::write(src.join("extra.conf"), "managed_extra\n").unwrap();

    let backup_root = tgt.join(".enstow-backup");

    // 1. Zero conflicts -> no backup dir created, no backup summary printed
    let out = Command::new(bin)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_BACKUP")
        .env_remove("ENSTOW_BACKUP_DIR")
        .args([
            "apply",
            "--backup",
            "-s",
            src.to_str().unwrap(),
            "-t",
            tgt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "zero-conflict apply failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!backup_root.exists());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("Backed up"),
        "unexpected backup summary on zero conflicts:\n{stdout}"
    );

    // 2. Dry-run with conflict -> no backup dir created, dry-run shows timestamped path, no summary
    fs::remove_file(tgt.join("app.conf")).unwrap();
    fs::write(tgt.join("app.conf"), "conflict_v1\n").unwrap();
    let out = Command::new(bin)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_BACKUP")
        .env_remove("ENSTOW_BACKUP_DIR")
        .args([
            "apply",
            "--backup",
            "--dry-run",
            "-s",
            src.to_str().unwrap(),
            "-t",
            tgt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(!backup_root.exists());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[dry-run] BACKUP"),
        "expected dry-run backup preview:\n{stdout}"
    );
    assert!(
        !stdout.contains("{timestamp}"),
        "dry-run should expand {{timestamp}} placeholder:\n{stdout}"
    );
    assert!(
        !stdout.contains("Backed up"),
        "dry-run should not print real backup summary:\n{stdout}"
    );

    // 3. First real --backup run (1 conflicting file)
    let out1 = Command::new(bin)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_BACKUP")
        .env_remove("ENSTOW_BACKUP_DIR")
        .args([
            "apply",
            "--backup",
            "-s",
            src.to_str().unwrap(),
            "-t",
            tgt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out1.status.success(),
        "run 1 apply failed: {}",
        String::from_utf8_lossy(&out1.stderr)
    );
    let stdout1 = String::from_utf8_lossy(&out1.stdout);
    let summary1 = stdout1
        .lines()
        .find(|l| l.starts_with("Backed up 1 file to "))
        .unwrap_or_else(|| panic!("missing backup summary in run 1:\n{stdout1}"));
    let dir1 = std::path::PathBuf::from(summary1.trim_start_matches("Backed up 1 file to "));
    assert_eq!(dir1.parent(), Some(backup_root.as_path()));
    assert_eq!(
        fs::read_to_string(dir1.join("app.conf")).unwrap(),
        "conflict_v1\n"
    );

    // 4. Second real --backup run (2 conflicting files) preserves run 1 and uses a new subdir
    fs::remove_file(tgt.join("app.conf")).unwrap();
    fs::write(tgt.join("app.conf"), "conflict_v2\n").unwrap();
    fs::remove_file(tgt.join("extra.conf")).unwrap();
    fs::write(tgt.join("extra.conf"), "extra_v1\n").unwrap();
    let out2 = Command::new(bin)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_BACKUP")
        .env_remove("ENSTOW_BACKUP_DIR")
        .args([
            "apply",
            "--backup",
            "-s",
            src.to_str().unwrap(),
            "-t",
            tgt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out2.status.success(),
        "run 2 apply failed: {}",
        String::from_utf8_lossy(&out2.stderr)
    );
    let stdout2 = String::from_utf8_lossy(&out2.stdout);
    let summary2 = stdout2
        .lines()
        .find(|l| l.starts_with("Backed up 2 files to "))
        .unwrap_or_else(|| panic!("missing backup summary in run 2:\n{stdout2}"));
    let dir2 = std::path::PathBuf::from(summary2.trim_start_matches("Backed up 2 files to "));
    assert_eq!(dir2.parent(), Some(backup_root.as_path()));
    assert_ne!(dir1, dir2);
    assert_eq!(
        fs::read_to_string(dir1.join("app.conf")).unwrap(),
        "conflict_v1\n"
    );
    assert_eq!(
        fs::read_to_string(dir2.join("app.conf")).unwrap(),
        "conflict_v2\n"
    );
    assert_eq!(
        fs::read_to_string(dir2.join("extra.conf")).unwrap(),
        "extra_v1\n"
    );

    // 5. Explicit --backup-dir without {timestamp} stays literal (no extra timestamp subdir)
    let literal_dir = temp.path().join("explicit-literal-backup");
    fs::remove_file(tgt.join("app.conf")).unwrap();
    fs::write(tgt.join("app.conf"), "literal_v1\n").unwrap();
    let out3 = Command::new(bin)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .env_remove("ENSTOW_BACKUP")
        .env_remove("ENSTOW_BACKUP_DIR")
        .args([
            "apply",
            "--backup",
            "--backup-dir",
            literal_dir.to_str().unwrap(),
            "-s",
            src.to_str().unwrap(),
            "-t",
            tgt.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out3.status.success(),
        "explicit literal backup failed: {}",
        String::from_utf8_lossy(&out3.stderr)
    );
    let stdout3 = String::from_utf8_lossy(&out3.stdout);
    assert!(
        stdout3.contains(&format!("Backed up 1 file to {}", literal_dir.display())),
        "expected literal backup dir in summary:\n{stdout3}"
    );
    assert_eq!(
        fs::read_to_string(literal_dir.join("app.conf")).unwrap(),
        "literal_v1\n"
    );
}

#[test]
fn test_cli_keygen_default_custom_overwrite_and_roundtrip() {
    let bin = env!("CARGO_BIN_EXE_enstow");

    match Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => {
            eprintln!("Skipping CLI keygen test: target binary cannot be executed");
            return;
        }
    }

    let temp = tempdir().unwrap();
    let xdg_dir = temp.path().join("xdg");
    let work_dir = temp.path().join("work");
    fs::create_dir_all(&xdg_dir).unwrap();
    fs::create_dir_all(&work_dir).unwrap();

    // 1. Default output uses XDG_CONFIG_HOME/sops/age/keys.txt
    let default_key_path = xdg_dir.join("sops").join("age").join("keys.txt");
    let out = Command::new(bin)
        .current_dir(&work_dir)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .args(["keygen"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "default keygen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(default_key_path.is_file());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let pubkey_line = stdout
        .lines()
        .find(|l| l.starts_with("Public key: age1"))
        .unwrap_or_else(|| panic!("missing public key in stdout:\n{stdout}"));
    let pubkey = pubkey_line.trim_start_matches("Public key: ").trim();
    assert!(!stdout.contains("AGE-SECRET-KEY-"));
    assert!(!stderr.contains("AGE-SECRET-KEY-"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&default_key_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    // 2. Refuses to overwrite existing default key without --force
    let orig_default_content = fs::read_to_string(&default_key_path).unwrap();
    let dup = Command::new(bin)
        .current_dir(&work_dir)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .args(["keygen"])
        .output()
        .unwrap();
    assert!(!dup.status.success(), "expected overwrite refusal");
    assert_eq!(
        fs::read_to_string(&default_key_path).unwrap(),
        orig_default_content
    );

    // 3. Overwrites when --force is passed
    let forced = Command::new(bin)
        .current_dir(&work_dir)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .args(["keygen", "--force"])
        .output()
        .unwrap();
    assert!(
        forced.status.success(),
        "forced keygen failed: {}",
        String::from_utf8_lossy(&forced.stderr)
    );
    let new_default_content = fs::read_to_string(&default_key_path).unwrap();
    assert_ne!(orig_default_content, new_default_content);

    // 4. Relative bare filename with -o in current working directory + full encrypt/decrypt round-trip
    let out_rel = Command::new(bin)
        .current_dir(&work_dir)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .args(["keygen", "-o", "local-keys.txt"])
        .output()
        .unwrap();
    assert!(
        out_rel.status.success(),
        "relative -o keygen failed: {}",
        String::from_utf8_lossy(&out_rel.stderr)
    );
    let local_key = work_dir.join("local-keys.txt");
    assert!(local_key.is_file());
    let rel_stdout = String::from_utf8_lossy(&out_rel.stdout);
    let rel_pubkey = rel_stdout
        .lines()
        .find(|l| l.starts_with("Public key: age1"))
        .unwrap_or_else(|| panic!("missing public key in stdout:\n{rel_stdout}"))
        .trim_start_matches("Public key: ")
        .trim();
    assert_ne!(pubkey, rel_pubkey);

    let plain = work_dir.join("token.env");
    let encrypted = work_dir.join("token.env.age");
    fs::write(&plain, "TOKEN=from_enstow_keygen\n").unwrap();

    let enc = Command::new(bin)
        .current_dir(&work_dir)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .args([
            "encrypt",
            plain.to_str().unwrap(),
            "-o",
            encrypted.to_str().unwrap(),
            "-r",
            rel_pubkey,
        ])
        .output()
        .unwrap();
    assert!(
        enc.status.success(),
        "encrypt with generated pubkey failed: {}",
        String::from_utf8_lossy(&enc.stderr)
    );

    let dec = Command::new(bin)
        .current_dir(&work_dir)
        .env("XDG_CONFIG_HOME", &xdg_dir)
        .env_remove("ENSTOW_CONFIG")
        .args([
            "decrypt",
            encrypted.to_str().unwrap(),
            "--age-key-file",
            local_key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        dec.status.success(),
        "decrypt with generated key failed: {}",
        String::from_utf8_lossy(&dec.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&dec.stdout),
        "TOKEN=from_enstow_keygen\n"
    );
}
