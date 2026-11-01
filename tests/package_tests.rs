use age::secrecy::ExposeSecret;
use age::Recipient;
use clap::Parser;
use enstow::cli::{Cli, Commands, CommonArgs};
use enstow::stow::{
    check_status, execute_plan, execute_unstow_plan, is_symlink_to, plan_stow, EntryStatus,
};
use std::fs;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_cli_parsing_packages_in_subcommands() {
    // 1. apply with packages
    let cli = Cli::try_parse_from(["enstow", "apply", "zsh", "nvim"]).unwrap();
    match cli.command {
        Some(Commands::Apply(args)) => {
            assert_eq!(args.packages, vec!["zsh", "nvim"]);
        }
        other => panic!("Expected Commands::Apply, got {:?}", other),
    }

    // 2. unstow with packages
    let cli = Cli::try_parse_from(["enstow", "unstow", "bash"]).unwrap();
    match cli.command {
        Some(Commands::Unstow(args)) => {
            assert_eq!(args.packages, vec!["bash"]);
        }
        other => panic!("Expected Commands::Unstow, got {:?}", other),
    }

    // 3. status with packages and flag
    let cli = Cli::try_parse_from(["enstow", "status", "--json", "zsh", "tmux"]).unwrap();
    match cli.command {
        Some(Commands::Status { common, json }) => {
            assert!(json);
            assert_eq!(common.packages, vec!["zsh", "tmux"]);
        }
        other => panic!("Expected Commands::Status, got {:?}", other),
    }

    // 4. default command with packages
    let cli = Cli::try_parse_from(["enstow", "zsh", "nvim"]).unwrap();
    assert!(cli.command.is_none());
    assert_eq!(cli.common.packages, vec!["zsh", "nvim"]);

    // 5. apply with no packages
    let cli = Cli::try_parse_from(["enstow", "apply"]).unwrap();
    match cli.command {
        Some(Commands::Apply(args)) => {
            assert!(args.packages.is_empty());
        }
        other => panic!("Expected Commands::Apply, got {:?}", other),
    }
}

#[test]
fn test_plan_stow_multiple_packages() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Package 1: zsh
    let zsh_dir = source_dir.path().join("zsh");
    fs::create_dir_all(&zsh_dir).unwrap();
    let zshrc = zsh_dir.join(".zshrc");
    fs::write(&zshrc, "export ZSH=1\n").unwrap();

    // Package 2: nvim
    let nvim_dir = source_dir.path().join("nvim").join(".config").join("nvim");
    fs::create_dir_all(&nvim_dir).unwrap();
    let init_lua = nvim_dir.join("init.lua");
    fs::write(&init_lua, "print('nvim')\n").unwrap();

    // Package 3: bash (should be ignored when only zsh & nvim specified)
    let bash_dir = source_dir.path().join("bash");
    fs::create_dir_all(&bash_dir).unwrap();
    let bashrc = bash_dir.join(".bashrc");
    fs::write(&bashrc, "export BASH=1\n").unwrap();

    let args = CommonArgs {
        source: source_dir.path().to_path_buf(),
        target: target_dir.path().to_path_buf(),
        dry_run: false,
        force: false,
        age_key_file: None,
        packages: vec!["zsh".to_string(), "nvim".to_string()],
    };

    let plan = plan_stow(&args).unwrap();
    assert_eq!(plan.len(), 2);

    let targets: Vec<_> = plan.iter().map(|a| a.target().to_path_buf()).collect();
    assert!(targets.contains(&target_dir.path().join(".zshrc")));
    assert!(targets.contains(
        &target_dir
            .path()
            .join(".config")
            .join("nvim")
            .join("init.lua")
    ));
    assert!(!targets.contains(&target_dir.path().join(".bashrc")));
}

#[test]
fn test_plan_stow_nonexistent_package_fails() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let args = CommonArgs {
        source: source_dir.path().to_path_buf(),
        target: target_dir.path().to_path_buf(),
        dry_run: false,
        force: false,
        age_key_file: None,
        packages: vec!["nonexistent".to_string()],
    };

    let result = plan_stow(&args);
    assert!(result.is_err());
}

#[test]
fn test_multi_package_stow_unstow_status_integration() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // Setup package 1: zsh with regular file
    let zsh_dir = source_dir.path().join("zsh");
    fs::create_dir_all(&zsh_dir).unwrap();
    let zshrc = zsh_dir.join(".zshrc");
    fs::write(&zshrc, "export ZSH=1\n").unwrap();

    // Setup package 2: secrets with age file
    let secret_pkg = source_dir.path().join("secrets");
    fs::create_dir_all(&secret_pkg).unwrap();
    let secret_age = secret_pkg.join("token.env.age");

    let key_dir = tempdir().unwrap();
    let key_file = key_dir.path().join("test_key.txt");
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    let plaintext = b"TOKEN=abc123secret\n";
    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(plaintext).unwrap();
    writer.finish().unwrap();
    fs::write(&secret_age, encrypted_buf).unwrap();

    // Setup package 3: tmux (unselected)
    let tmux_dir = source_dir.path().join("tmux");
    fs::create_dir_all(&tmux_dir).unwrap();
    let tmux_conf = tmux_dir.join(".tmux.conf");
    fs::write(&tmux_conf, "set -g mouse on\n").unwrap();

    // 1. Stow only zsh and secrets
    let args_apply = CommonArgs {
        source: source_dir.path().to_path_buf(),
        target: target_dir.path().to_path_buf(),
        dry_run: false,
        force: false,
        age_key_file: Some(key_file.clone()),
        packages: vec!["zsh".to_string(), "secrets".to_string()],
    };

    let plan = plan_stow(&args_apply).unwrap();
    assert_eq!(plan.len(), 2);
    execute_plan(&plan, false, Some(&key_file), false).unwrap();

    let target_zshrc = target_dir.path().join(".zshrc");
    let target_token = target_dir.path().join("token.env");
    let target_tmux = target_dir.path().join(".tmux.conf");

    assert!(target_zshrc.exists());
    assert!(is_symlink_to(&target_zshrc, &zshrc));
    assert!(target_token.exists());
    assert_eq!(fs::read(&target_token).unwrap(), plaintext);
    assert!(!target_tmux.exists());

    // 2. Status for zsh only
    let args_status_zsh = CommonArgs {
        source: source_dir.path().to_path_buf(),
        target: target_dir.path().to_path_buf(),
        dry_run: false,
        force: false,
        age_key_file: None,
        packages: vec!["zsh".to_string()],
    };
    let plan_status = plan_stow(&args_status_zsh).unwrap();
    assert_eq!(plan_status.len(), 1);
    let statuses = check_status(&plan_status, None).unwrap();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0].status, EntryStatus::Synced);

    // 3. Unstow zsh only
    let args_unstow_zsh = CommonArgs {
        source: source_dir.path().to_path_buf(),
        target: target_dir.path().to_path_buf(),
        dry_run: false,
        force: false,
        age_key_file: None,
        packages: vec!["zsh".to_string()],
    };
    let plan_unstow = plan_stow(&args_unstow_zsh).unwrap();
    execute_unstow_plan(&plan_unstow, target_dir.path(), false).unwrap();

    // zshrc unlinked, but secret token preserved
    assert!(!target_zshrc.exists());
    assert!(target_token.exists());
}
