use age::secrecy::ExposeSecret;
use age::Recipient;
use clap::Parser;
use enstow::cli::{Cli, Commands};
use enstow::crypto::{edit_file_age, edit_file_age_returning_plaintext};
use enstow::stow::{deploy_edited_secret, resolve_secret_target};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use tempfile::tempdir;

static ENV_MUTEX: Mutex<()> = Mutex::new(());

fn setup_age_key_and_file(key_path: &Path, secret_path: &Path, plaintext: &[u8]) {
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
    let status = std::process::Command::new("rustc")
        .arg(&source_path)
        .arg("-o")
        .arg(&bin_path)
        .status()
        .expect("Failed to invoke rustc");
    assert!(status.success(), "Failed to compile mock editor");
    bin_path
}

#[test]
fn test_cli_parsing_edit() {
    let cli = Cli::try_parse_from([
        "enstow",
        "edit",
        "secret.env.age",
        "--age-key-file",
        "/path/to/key.txt",
        "--editor",
        "nano",
    ])
    .unwrap();

    match cli.command {
        Some(Commands::Edit {
            file,
            recipient,
            age_key_file,
            editor,
            apply,
            source,
            target,
        }) => {
            assert_eq!(file.to_str().unwrap(), "secret.env.age");
            assert!(recipient.is_empty());
            assert_eq!(age_key_file.unwrap().to_str().unwrap(), "/path/to/key.txt");
            assert_eq!(editor.unwrap(), "nano");
            assert!(!apply);
            assert!(source.is_none());
            assert!(target.is_none());
        }
        _ => panic!("Expected Commands::Edit"),
    }
}

#[test]
fn test_edit_file_age_modifies_and_reencrypts() {
    let dir = tempdir().unwrap();
    let key_file = dir.path().join("key.txt");
    let secret_file = dir.path().join("app.env.age");
    setup_age_key_and_file(&key_file, &secret_file, b"INITIAL_SECRET=123\n");

    let editor_bin = compile_mock_editor(dir.path(), Some("UPDATED_SECRET=456\n"), 0);
    let editor_cmd = editor_bin.to_str().unwrap();

    let modified = edit_file_age(&secret_file, &[], Some(&key_file), Some(editor_cmd)).unwrap();
    assert!(modified);

    // Verify decrypted content contains updated secret
    let decrypted = enstow::crypto::decrypt_age(&secret_file, Some(&key_file)).unwrap();
    assert_eq!(decrypted, b"UPDATED_SECRET=456\n");
}

#[test]
fn test_edit_file_age_unchanged_does_not_reencrypt() {
    let dir = tempdir().unwrap();
    let key_file = dir.path().join("key.txt");
    let secret_file = dir.path().join("app.env.age");
    setup_age_key_and_file(&key_file, &secret_file, b"UNCHANGED_SECRET=999\n");

    let editor_bin = compile_mock_editor(dir.path(), None, 0);
    let editor_cmd = editor_bin.to_str().unwrap();

    let modified = edit_file_age(&secret_file, &[], Some(&key_file), Some(editor_cmd)).unwrap();
    assert!(!modified);

    let decrypted = enstow::crypto::decrypt_age(&secret_file, Some(&key_file)).unwrap();
    assert_eq!(decrypted, b"UNCHANGED_SECRET=999\n");
}

#[test]
fn test_edit_file_age_editor_failure_errors() {
    let dir = tempdir().unwrap();
    let key_file = dir.path().join("key.txt");
    let secret_file = dir.path().join("app.env.age");
    setup_age_key_and_file(&key_file, &secret_file, b"SECRET_VALUE=1\n");

    let editor_bin = compile_mock_editor(dir.path(), None, 1);
    let editor_cmd = editor_bin.to_str().unwrap();

    let result = edit_file_age(&secret_file, &[], Some(&key_file), Some(editor_cmd));
    assert!(result.is_err());

    // File content remains original
    let decrypted = enstow::crypto::decrypt_age(&secret_file, Some(&key_file)).unwrap();
    assert_eq!(decrypted, b"SECRET_VALUE=1\n");
}

#[test]
fn test_edit_file_age_nonexistent_file_errors() {
    let dir = tempdir().unwrap();
    let key_file = dir.path().join("key.txt");
    let missing_file = dir.path().join("nonexistent.env.age");

    let result = edit_file_age(&missing_file, &[], Some(&key_file), Some("true"));
    assert!(result.is_err());
}

#[test]
fn test_edit_file_age_env_editor_and_whitespace_args() {
    let _lock = ENV_MUTEX.lock().unwrap();
    let dir = tempdir().unwrap();
    let key_file = dir.path().join("key.txt");
    let secret_file = dir.path().join("app.env.age");
    setup_age_key_and_file(&key_file, &secret_file, b"INITIAL=1\n");

    let editor_bin = compile_mock_editor(dir.path(), Some("FROM_ENV_EDITOR=2\n"), 0);

    let orig_enstow_ed = std::env::var("ENSTOW_EDITOR").ok();
    let orig_visual = std::env::var("VISUAL").ok();
    let orig_editor = std::env::var("EDITOR").ok();

    // 1. ENSTOW_EDITOR with split whitespace command
    let editor_cmd = format!("{} --some-unused-arg", editor_bin.display());
    std::env::set_var("ENSTOW_EDITOR", &editor_cmd);
    std::env::remove_var("VISUAL");
    std::env::remove_var("EDITOR");

    let modified = edit_file_age(&secret_file, &[], Some(&key_file), None).unwrap();
    assert!(modified);
    let decrypted = enstow::crypto::decrypt_age(&secret_file, Some(&key_file)).unwrap();
    assert_eq!(decrypted, b"FROM_ENV_EDITOR=2\n");

    // 2. VISUAL fallback
    std::env::remove_var("ENSTOW_EDITOR");
    std::env::set_var("VISUAL", editor_bin.to_str().unwrap());
    let modified = edit_file_age(&secret_file, &[], Some(&key_file), None).unwrap();
    // content unchanged because editor output matches existing
    assert!(!modified);

    // 3. EDITOR fallback
    std::env::remove_var("VISUAL");
    std::env::set_var("EDITOR", editor_bin.to_str().unwrap());
    let modified = edit_file_age(&secret_file, &[], Some(&key_file), None).unwrap();
    assert!(!modified);

    std::env::remove_var("ENSTOW_EDITOR");
    std::env::remove_var("VISUAL");
    std::env::remove_var("EDITOR");
    if let Some(v) = orig_enstow_ed {
        std::env::set_var("ENSTOW_EDITOR", v);
    }
    if let Some(v) = orig_visual {
        std::env::set_var("VISUAL", v);
    }
    if let Some(v) = orig_editor {
        std::env::set_var("EDITOR", v);
    }
}

#[test]
fn test_cli_parsing_edit_apply() {
    let cli = Cli::try_parse_from([
        "enstow",
        "edit",
        "bash/.tokens.age",
        "--apply",
        "-s",
        "/repo",
        "-t",
        "/home/user",
    ])
    .unwrap();

    match cli.command {
        Some(Commands::Edit {
            file,
            apply,
            source,
            target,
            ..
        }) => {
            assert_eq!(file.to_str().unwrap(), "bash/.tokens.age");
            assert!(apply);
            assert_eq!(source.unwrap().to_str().unwrap(), "/repo");
            assert_eq!(target.unwrap().to_str().unwrap(), "/home/user");
        }
        other => panic!("Expected Commands::Edit, got {:?}", other),
    }
}

#[test]
fn test_resolve_secret_target_and_deploy_edited_secret() {
    let workspace = tempdir().unwrap();
    let repo = workspace.path().join("dotfiles");
    let target = workspace.path().join("target");
    let key_dir = workspace.path().join("keys");
    let editor_dir = workspace.path().join("editors");
    fs::create_dir_all(repo.join("bash")).unwrap();
    fs::create_dir_all(repo.join("pvetui").join(".config").join("pvetui")).unwrap();
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&key_dir).unwrap();
    fs::create_dir_all(&editor_dir).unwrap();

    let key_file = key_dir.join("keys.txt");
    let tokens_age = repo.join("bash").join(".tokens.age");
    setup_age_key_and_file(&key_file, &tokens_age, b"TOKEN=old\n");

    let pvetui_age = repo
        .join("pvetui")
        .join(".config")
        .join("pvetui")
        .join("config.yml.age");
    fs::write(&pvetui_age, b"dummy").unwrap();

    // 1. Resolve packaged and nested paths
    let resolved_tokens = resolve_secret_target(
        &tokens_age,
        &repo,
        &target,
        &["bash".to_string(), "pvetui".to_string()],
    )
    .unwrap();
    assert_eq!(resolved_tokens, target.join(".tokens"));

    let resolved_pvetui = resolve_secret_target(
        &pvetui_age,
        &repo,
        &target,
        &["bash".to_string(), "pvetui".to_string()],
    )
    .unwrap();
    assert_eq!(
        resolved_pvetui,
        target.join(".config").join("pvetui").join("config.yml")
    );

    // 2. File outside source errors
    let outside = workspace.path().join("outside.age");
    fs::write(&outside, b"dummy").unwrap();
    assert!(resolve_secret_target(&outside, &repo, &target, &["bash".to_string()]).is_err());

    // 3. Edit and deploy updated plaintext with custom permissions
    let editor_update = compile_mock_editor(&editor_dir, Some("TOKEN=new\n"), 0);
    let updated = edit_file_age_returning_plaintext(
        &tokens_age,
        &[],
        Some(&key_file),
        Some(editor_update.to_str().unwrap()),
    )
    .unwrap()
    .expect("expected modified plaintext");
    assert_eq!(updated, b"TOKEN=new\n");

    let mut perms = enstow::config::PermissionsConfig::new();
    perms.add_rule(".tokens".into(), 0o600, None);
    let mode = deploy_edited_secret(
        &tokens_age,
        &resolved_tokens,
        &target,
        &updated,
        Some(&perms),
    )
    .unwrap();
    assert_eq!(mode, 0o600);
    assert_eq!(fs::read(&resolved_tokens).unwrap(), b"TOKEN=new\n");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&resolved_tokens).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // 4. Unchanged edit returns None
    let editor_noop = compile_mock_editor(&editor_dir, None, 0);
    let unchanged = edit_file_age_returning_plaintext(
        &tokens_age,
        &[],
        Some(&key_file),
        Some(editor_noop.to_str().unwrap()),
    )
    .unwrap();
    assert!(unchanged.is_none());
}

#[test]
fn test_cli_edit_apply_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_enstow");
    match std::process::Command::new(bin).arg("--version").output() {
        Ok(o) if o.status.success() => {}
        _ => return,
    }

    let workspace = tempdir().unwrap();
    let repo = workspace.path().join("dotfiles");
    let target = workspace.path().join("target");
    let key_dir = workspace.path().join("keys");
    let editor_dir = workspace.path().join("editors");
    fs::create_dir_all(repo.join("bash")).unwrap();
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&key_dir).unwrap();
    fs::create_dir_all(&editor_dir).unwrap();

    let key_file = key_dir.join("keys.txt");
    let tokens_age = repo.join("bash").join(".tokens.age");
    setup_age_key_and_file(&key_file, &tokens_age, b"TOKEN=initial\n");
    fs::write(
        repo.join(".enstow.toml"),
        "source = \".\"\npackages = [\"bash\"]\n",
    )
    .unwrap();

    // Deploy initial secret
    let deployed = target.join(".tokens");
    fs::write(&deployed, b"TOKEN=initial\n").unwrap();

    // 1. `enstow edit --apply` with modified content updates BOTH .age source and deployed target
    let editor_update = compile_mock_editor(&editor_dir, Some("TOKEN=rotated\n"), 0);
    let out = std::process::Command::new(bin)
        .current_dir(&repo)
        .env_remove("ENSTOW_CONFIG")
        .args([
            "edit",
            "bash/.tokens.age",
            "--apply",
            "-t",
            target.to_str().unwrap(),
            "--age-key-file",
            key_file.to_str().unwrap(),
            "--editor",
            editor_update.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "edit --apply failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        enstow::crypto::decrypt_age(&tokens_age, Some(&key_file)).unwrap(),
        b"TOKEN=rotated\n"
    );
    assert_eq!(fs::read(&deployed).unwrap(), b"TOKEN=rotated\n");

    // 2. `enstow edit --apply` with NO editor changes leaves deployed target untouched
    fs::write(&deployed, b"TOKEN=untouched_marker\n").unwrap();
    let editor_noop = compile_mock_editor(&editor_dir, None, 0);
    let noop_out = std::process::Command::new(bin)
        .current_dir(&repo)
        .env_remove("ENSTOW_CONFIG")
        .args([
            "edit",
            "bash/.tokens.age",
            "--apply",
            "-t",
            target.to_str().unwrap(),
            "--age-key-file",
            key_file.to_str().unwrap(),
            "--editor",
            editor_noop.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(noop_out.status.success());
    assert_eq!(fs::read(&deployed).unwrap(), b"TOKEN=untouched_marker\n");
}
