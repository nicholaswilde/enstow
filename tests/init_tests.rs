use age::secrecy::ExposeSecret;
use age::Recipient;
use clap::Parser;
use enstow::cli::{default_dotfiles_dir, Cli, Commands, InitArgs};
use enstow::config::{
    detect_host_packages, detect_host_profile, discover_repo_config, resolve_init_source, HostInfo,
};
use enstow::crypto::{
    default_age_key_file, find_existing_age_key, has_valid_identity, import_age_key,
};
use enstow::init::{clone_repository, run_init, run_init_with_io};
use enstow::stow::is_symlink_to;
use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::tempdir;

fn init_git_repo(repo_dir: &Path) {
    let run_git = |args: &[&str]| {
        let status = Command::new("git")
            .args(args)
            .current_dir(repo_dir)
            .env("GIT_AUTHOR_NAME", "Test User")
            .env("GIT_AUTHOR_EMAIL", "test@example.com")
            .env("GIT_COMMITTER_NAME", "Test User")
            .env("GIT_COMMITTER_EMAIL", "test@example.com")
            .output()
            .expect("Failed to run git");
        assert!(
            status.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&status.stderr)
        );
    };

    run_git(&["init"]);
    run_git(&["config", "core.autocrlf", "false"]);
    run_git(&["add", "."]);
    run_git(&["commit", "-m", "initial commit"]);
}

fn encrypt_age_bytes(plaintext: &[u8], pubkey: &age::x25519::Recipient) -> Vec<u8> {
    loop {
        let recipient: &dyn Recipient = pubkey;
        let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
        let mut encrypted = Vec::new();
        let mut writer = encryptor.wrap_output(&mut encrypted).unwrap();
        writer.write_all(plaintext).unwrap();
        writer.finish().unwrap();
        if !encrypted.contains(&0) {
            return encrypted;
        }
    }
}

#[test]
fn test_cli_parsing_init_subcommand() {
    let cli = Cli::try_parse_from([
        "enstow",
        "init",
        "https://github.com/example/dotfiles.git",
        "-s",
        "/tmp/my-dotfiles",
        "-t",
        "/tmp/my-home",
        "--branch",
        "main",
        "--profile",
        "work",
        "-p",
        "zsh",
        "-p",
        "git",
        "-n",
        "-f",
        "-b",
        "--prune",
        "--adopt",
        "-I",
    ])
    .unwrap();

    match cli.command {
        Some(Commands::Init(args)) => {
            assert_eq!(
                args.repo.as_deref(),
                Some("https://github.com/example/dotfiles.git")
            );
            assert_eq!(args.branch.as_deref(), Some("main"));
            assert_eq!(
                args.source,
                Some(std::path::PathBuf::from("/tmp/my-dotfiles"))
            );
            assert_eq!(args.target, Some(std::path::PathBuf::from("/tmp/my-home")));
            assert_eq!(args.profile.as_deref(), Some("work"));
            assert_eq!(args.packages, vec!["zsh", "git"]);
            assert!(args.dry_run);
            assert!(args.force);
            assert!(args.backup);
            assert!(args.prune);
            assert!(args.adopt);
            assert!(args.interactive);
        }
        other => panic!("Expected Commands::Init, got {:?}", other),
    }

    let default_src = resolve_init_source(None, None);
    assert!(default_src.ends_with(".dotfiles"));
    assert!(default_dotfiles_dir().ends_with(".dotfiles"));
    assert!(default_age_key_file().ends_with("keys.txt"));
}

#[test]
fn test_init_clones_repo_and_applies_dotfiles() {
    let remote = tempdir().unwrap();
    let work = tempdir().unwrap();
    let source_dest = work.path().join(".dotfiles");
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let key = age::x25519::Identity::generate();
    let key_file = key_dir.path().join("keys.txt");
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    fs::write(remote.path().join(".bashrc"), "export HELLO=world\n").unwrap();
    let secret_bytes = encrypt_age_bytes(b"API_TOKEN=secret123\n", &key.to_public());
    fs::write(remote.path().join(".env.age"), secret_bytes).unwrap();
    init_git_repo(remote.path());

    let args = InitArgs {
        repo: Some(remote.path().to_string_lossy().into_owned()),
        source: Some(source_dest.clone()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_file),
        ..Default::default()
    };

    let report = run_init(&args, None).unwrap();
    assert!(report.cloned);
    assert!(source_dest.join(".git").exists());
    assert!(report.doctor.healthy);
    assert_eq!(report.applied_actions, 2);

    assert!(is_symlink_to(
        &target_dir.path().join(".bashrc"),
        &source_dest.join(".bashrc")
    ));
    let decrypted_env = target_dir.path().join(".env");
    assert!(decrypted_env.exists());
    assert_eq!(
        fs::read_to_string(&decrypted_env).unwrap(),
        "API_TOKEN=secret123\n"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::symlink_metadata(&decrypted_env)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    let mut args_second = args.clone();
    args_second.force = true;
    let report_second = run_init(&args_second, None).unwrap();
    assert!(!report_second.cloned);
    assert!(report_second.doctor.healthy);
}

#[test]
fn test_init_auto_detects_host_profile_and_packages() {
    let repo_dir = tempdir().unwrap();
    let target_linux = tempdir().unwrap();
    let target_mac = tempdir().unwrap();
    let target_host = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let key = age::x25519::Identity::generate();
    let key_file = key_dir.path().join("keys.txt");
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    for pkg in ["common", "linux_wm", "macos_wm", "workstation_tools"] {
        let p = repo_dir.path().join(pkg);
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join(format!(".{pkg}")), format!("{pkg}=1\n")).unwrap();
    }

    let enstow_toml = r#"
[profiles.linux]
packages = ["common", "linux_wm"]

[profiles.macos-aarch64]
packages = ["common", "macos_wm"]

[profiles.devbox]
packages = ["common", "linux_wm", "workstation_tools"]
"#;
    fs::write(repo_dir.path().join("enstow.toml"), enstow_toml).unwrap();

    let (_, discovered) = discover_repo_config(repo_dir.path()).unwrap().unwrap();

    let linux_host = HostInfo {
        os: "linux".into(),
        arch: "x86_64".into(),
        hostname: "generic-pc".into(),
    };
    assert_eq!(
        detect_host_profile(Some(&discovered), &linux_host).as_deref(),
        Some("linux")
    );

    let mac_arm_host = HostInfo {
        os: "macos".into(),
        arch: "aarch64".into(),
        hostname: "macbook".into(),
    };
    assert_eq!(
        detect_host_profile(Some(&discovered), &mac_arm_host).as_deref(),
        Some("macos-aarch64")
    );

    let devbox_host = HostInfo {
        os: "linux".into(),
        arch: "x86_64".into(),
        hostname: "devbox.local".into(),
    };
    assert_eq!(
        detect_host_profile(Some(&discovered), &devbox_host).as_deref(),
        Some("devbox")
    );

    let mut input = Cursor::new(b"");
    let mut output = Vec::new();

    let args_linux = InitArgs {
        source: Some(repo_dir.path().to_path_buf()),
        target: Some(target_linux.path().to_path_buf()),
        age_key_file: Some(key_file.clone()),
        ..Default::default()
    };
    let rep_linux = run_init_with_io(
        &args_linux,
        None,
        Some(&linux_host),
        &mut input,
        &mut output,
    )
    .unwrap();
    assert_eq!(rep_linux.profile.as_deref(), Some("linux"));
    assert_eq!(rep_linux.packages, vec!["common", "linux_wm"]);
    assert!(target_linux.path().join(".common").exists());
    assert!(target_linux.path().join(".linux_wm").exists());
    assert!(fs::symlink_metadata(target_linux.path().join(".macos_wm")).is_err());
    assert!(fs::symlink_metadata(target_linux.path().join("enstow.toml")).is_err());

    let args_mac = InitArgs {
        source: Some(repo_dir.path().to_path_buf()),
        target: Some(target_mac.path().to_path_buf()),
        age_key_file: Some(key_file.clone()),
        ..Default::default()
    };
    let rep_mac = run_init_with_io(
        &args_mac,
        None,
        Some(&mac_arm_host),
        &mut input,
        &mut output,
    )
    .unwrap();
    assert_eq!(rep_mac.profile.as_deref(), Some("macos-aarch64"));
    assert_eq!(rep_mac.packages, vec!["common", "macos_wm"]);
    assert!(target_mac.path().join(".common").exists());
    assert!(target_mac.path().join(".macos_wm").exists());
    assert!(fs::symlink_metadata(target_mac.path().join(".linux_wm")).is_err());

    let args_host = InitArgs {
        source: Some(repo_dir.path().to_path_buf()),
        target: Some(target_host.path().to_path_buf()),
        age_key_file: Some(key_file),
        ..Default::default()
    };
    let rep_host = run_init_with_io(
        &args_host,
        None,
        Some(&devbox_host),
        &mut input,
        &mut output,
    )
    .unwrap();
    assert_eq!(rep_host.profile.as_deref(), Some("devbox"));
    assert_eq!(
        rep_host.packages,
        vec!["common", "linux_wm", "workstation_tools"]
    );
    assert!(target_host.path().join(".workstation_tools").exists());
}

#[test]
fn test_init_auto_detects_package_directories_without_config() {
    let repo_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let key = age::x25519::Identity::generate();
    let key_file = key_dir.path().join("keys.txt");
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    for pkg in ["common", "zsh", "linux", "macos", "windows"] {
        let p = repo_dir.path().join(pkg);
        fs::create_dir_all(&p).unwrap();
        fs::write(p.join(format!(".{pkg}rc")), format!("# {pkg}\n")).unwrap();
    }

    let linux_host = HostInfo {
        os: "linux".into(),
        arch: "x86_64".into(),
        hostname: "box".into(),
    };
    let detected = detect_host_packages(repo_dir.path(), None, &linux_host);
    assert_eq!(detected, vec!["common", "linux", "zsh"]);

    let args = InitArgs {
        source: Some(repo_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_file),
        ..Default::default()
    };
    let mut input = Cursor::new(b"");
    let mut output = Vec::new();
    let report = run_init_with_io(&args, None, Some(&linux_host), &mut input, &mut output).unwrap();
    assert_eq!(report.packages, vec!["common", "linux", "zsh"]);
    assert!(target_dir.path().join(".commonrc").exists());
    assert!(target_dir.path().join(".linuxrc").exists());
    assert!(target_dir.path().join(".zshrc").exists());
    assert!(fs::symlink_metadata(target_dir.path().join(".macosrc")).is_err());
    assert!(fs::symlink_metadata(target_dir.path().join(".windowsrc")).is_err());
}

#[test]
fn test_init_prompts_and_imports_age_key_from_string_and_file() {
    let repo_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let key = age::x25519::Identity::generate();
    let secret_key_str = key.to_string();
    let pubkey = key.to_public();

    let encrypted = encrypt_age_bytes(b"DB_PASS=topsecret\n", &pubkey);
    fs::write(repo_dir.path().join("db.env.age"), encrypted).unwrap();

    let imported_key_path = key_dir.path().join("imported").join("keys.txt");
    assert!(!imported_key_path.exists());
    assert!(find_existing_age_key(Some(&imported_key_path)).is_none());

    let args = InitArgs {
        source: Some(repo_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(imported_key_path.clone()),
        ..Default::default()
    };

    let prompt_input = format!("{}\n", secret_key_str.expose_secret());
    let mut reader = Cursor::new(prompt_input.into_bytes());
    let mut writer = Vec::new();

    let report = run_init_with_io(&args, None, None, &mut reader, &mut writer).unwrap();
    let prompt_text = String::from_utf8(writer).unwrap();
    assert!(prompt_text.contains("No age identity key found"));
    assert_eq!(report.age_key_file, Some(imported_key_path.clone()));
    assert!(has_valid_identity(&imported_key_path));
    assert_eq!(
        fs::read_to_string(target_dir.path().join("db.env")).unwrap(),
        "DB_PASS=topsecret\n"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::symlink_metadata(&imported_key_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    let dest_from_file = key_dir.path().join("from_file").join("keys.txt");
    import_age_key(imported_key_path.to_str().unwrap(), &dest_from_file, false).unwrap();
    assert!(has_valid_identity(&dest_from_file));

    let bad_dest = key_dir.path().join("bad_keys.txt");
    let err = import_age_key("not-a-valid-age-key", &bad_dest, false).unwrap_err();
    assert!(err.to_string().contains("Invalid age identity key"));
}

#[test]
fn test_init_preflight_check_blocks_on_errors_and_dry_run_previews() {
    let remote = tempdir().unwrap();
    let work = tempdir().unwrap();
    let source_dest = work.path().join(".dotfiles");
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let key = age::x25519::Identity::generate();
    let key_file = key_dir.path().join("keys.txt");
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    fs::write(remote.path().join(".gitconfig"), "[user]\nname = Test\n").unwrap();
    init_git_repo(remote.path());

    let dry_args = InitArgs {
        repo: Some(remote.path().to_string_lossy().into_owned()),
        source: Some(source_dest.clone()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_file.clone()),
        dry_run: true,
        ..Default::default()
    };
    let mut reader = Cursor::new(b"");
    let mut writer = Vec::new();
    let dry_report = run_init_with_io(&dry_args, None, None, &mut reader, &mut writer).unwrap();
    assert!(dry_report.cloned);
    assert_eq!(dry_report.applied_actions, 1);
    assert!(!source_dest.exists());
    assert!(fs::symlink_metadata(target_dir.path().join(".gitconfig")).is_err());

    let bad_repo = tempdir().unwrap();
    fs::create_dir_all(bad_repo.path().join("pkg1")).unwrap();
    fs::create_dir_all(bad_repo.path().join("pkg2")).unwrap();
    fs::write(bad_repo.path().join("pkg1").join(".vimrc"), "set number\n").unwrap();
    fs::write(bad_repo.path().join("pkg2").join(".vimrc"), "syntax on\n").unwrap();

    let bad_args = InitArgs {
        source: Some(bad_repo.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_file),
        packages: vec!["pkg1".into(), "pkg2".into()],
        ..Default::default()
    };
    let err = run_init_with_io(&bad_args, None, None, &mut reader, &mut writer).unwrap_err();
    assert!(err.to_string().contains("Pre-flight check failed"));
    assert!(fs::symlink_metadata(target_dir.path().join(".vimrc")).is_err());
}

#[test]
fn test_clone_repository_collision_and_force() {
    let remote = tempdir().unwrap();
    fs::write(remote.path().join(".bashrc"), "# bash\n").unwrap();
    init_git_repo(remote.path());

    let dest = tempdir().unwrap();
    fs::write(dest.path().join("unmanaged.txt"), "conflict").unwrap();

    let err = clone_repository(
        remote.path().to_str().unwrap(),
        dest.path(),
        None,
        false,
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("collision"));

    let cloned = clone_repository(
        remote.path().to_str().unwrap(),
        dest.path(),
        None,
        true,
        false,
    )
    .unwrap();
    assert!(cloned);
    assert!(dest.path().join(".git").exists());
    assert!(dest.path().join(".bashrc").exists());
}

#[test]
fn test_cli_init_end_to_end_binary() {
    let bin = env!("CARGO_BIN_EXE_enstow");
    match Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => return,
    }

    let remote = tempdir().unwrap();
    let work = tempdir().unwrap();
    let source_dest = work.path().join(".dotfiles");
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();
    let key_path = key_dir.path().join("keys.txt");

    let key = age::x25519::Identity::generate();
    let secret_str = key.to_string();
    let encrypted = encrypt_age_bytes(b"SECRET_VAL=42\n", &key.to_public());

    fs::write(remote.path().join(".profile"), "export PATH=$PATH\n").unwrap();
    fs::write(remote.path().join(".secret.age"), encrypted).unwrap();
    init_git_repo(remote.path());

    let mut child = Command::new(bin)
        .args([
            "init",
            remote.path().to_str().unwrap(),
            "-s",
            source_dest.to_str().unwrap(),
            "-t",
            target_dir.path().to_str().unwrap(),
            "--age-key-file",
            key_path.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        writeln!(stdin, "{}", secret_str.expose_secret()).unwrap();
    }

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Initialized"));
    assert!(is_symlink_to(
        &target_dir.path().join(".profile"),
        &source_dest.join(".profile")
    ));
    assert_eq!(
        fs::read_to_string(target_dir.path().join(".secret")).unwrap(),
        "SECRET_VAL=42\n"
    );
}
