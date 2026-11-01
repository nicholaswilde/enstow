use age::secrecy::ExposeSecret;
use age::Recipient;
use enstow::cli::CommonArgs;
use enstow::stow::{execute_plan, plan_stow};
use std::fs;
use std::io::Write;
use tempfile::tempdir;

#[test]
fn test_end_to_end_nested_stow_with_mixed_regular_and_age_files() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    // 1. Setup nested regular dotfiles
    let bash_dir = source_dir.path().join(".config/bash");
    fs::create_dir_all(&bash_dir).unwrap();
    let bashrc = bash_dir.join("bashrc");
    fs::write(&bashrc, "export FOO=bar\n").unwrap();

    let root_file = source_dir.path().join(".profile");
    fs::write(&root_file, "# profile\n").unwrap();

    // 2. Setup age encrypted secret inside nested dir
    let auth_dir = source_dir.path().join(".config/gh");
    fs::create_dir_all(&auth_dir).unwrap();
    let hosts_age = auth_dir.join("hosts.yml.age");

    let key_dir = tempdir().unwrap();
    let key_file = key_dir.path().join("test_key.txt");
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    let plaintext_secret = b"github.com:\n  oauth_token: gho_secret123\n";
    let recipient: &dyn Recipient = &pubkey;
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
    let mut encrypted_buf = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted_buf).unwrap();
    writer.write_all(plaintext_secret).unwrap();
    writer.finish().unwrap();
    fs::write(&hosts_age, encrypted_buf).unwrap();

    let args = CommonArgs {
        source: source_dir.path().to_path_buf(),
        target: target_dir.path().to_path_buf(),
        dry_run: false,
        force: false,
        age_key_file: Some(key_file.clone()),
    };

    // 3. Plan stow
    let plan = plan_stow(&args).unwrap();
    assert_eq!(plan.len(), 3); // bashrc, .profile, hosts.yml.age

    // 4. Dry run verification: ensure no target files exist
    execute_plan(&plan, true, Some(&key_file), false).unwrap();
    assert!(!target_dir.path().join(".config/bash/bashrc").exists());
    assert!(!target_dir.path().join(".profile").exists());
    assert!(!target_dir.path().join(".config/gh/hosts.yml").exists());

    // 5. Real execution
    execute_plan(&plan, false, Some(&key_file), false).unwrap();

    // 6. Verify regular symlinks
    let target_bashrc = target_dir.path().join(".config/bash/bashrc");
    assert!(fs::symlink_metadata(&target_bashrc)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_link(&target_bashrc).unwrap(), bashrc);

    let target_profile = target_dir.path().join(".profile");
    assert!(fs::symlink_metadata(&target_profile)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read_link(&target_profile).unwrap(), root_file);

    // 7. Verify decrypted file and Unix permissions
    let target_hosts = target_dir.path().join(".config/gh/hosts.yml");
    assert!(target_hosts.exists());
    assert!(!fs::symlink_metadata(&target_hosts)
        .unwrap()
        .file_type()
        .is_symlink());
    assert_eq!(fs::read(&target_hosts).unwrap(), plaintext_secret);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&target_hosts).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
