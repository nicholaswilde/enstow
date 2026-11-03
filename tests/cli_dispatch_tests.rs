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
