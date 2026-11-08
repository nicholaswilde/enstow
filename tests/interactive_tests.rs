use age::secrecy::ExposeSecret;
use age::Recipient;
use clap::Parser;
use enstow::cli::{Cli, Commands, CommonArgs};
use enstow::config::{resolve_common_args, ConfigFile, ConfigFormat};
use enstow::stow::{
    execute_plan_interactive_with_io, is_symlink_to, plan_stow, prompt_conflict_resolution,
    ConflictResolution, FileAction,
};
use std::fs;
use std::io::{Cursor, Write};
use tempfile::tempdir;

#[test]
fn test_cli_parsing_interactive_flag() {
    let cli = Cli::try_parse_from(["enstow", "apply", "--interactive"]).unwrap();
    match cli.command {
        Some(Commands::Apply(args)) => assert!(args.interactive),
        other => panic!("Expected Commands::Apply, got {:?}", other),
    }

    let cli_short = Cli::try_parse_from(["enstow", "apply", "-I"]).unwrap();
    match cli_short.command {
        Some(Commands::Apply(args)) => assert!(args.interactive),
        other => panic!("Expected Commands::Apply, got {:?}", other),
    }

    // Verify -i remains bound to --ignore
    let cli_both = Cli::try_parse_from(["enstow", "apply", "-I", "-i", "*.bak"]).unwrap();
    match cli_both.command {
        Some(Commands::Apply(args)) => {
            assert!(args.interactive);
            assert_eq!(args.ignore, vec!["*.bak"]);
        }
        other => panic!("Expected Commands::Apply, got {:?}", other),
    }
}

#[test]
fn test_config_interactive_precedence() {
    let cfg = ConfigFile::parse("interactive = true\n", ConfigFormat::Toml).unwrap();
    assert_eq!(cfg.interactive, Some(true));

    let resolved = resolve_common_args(&CommonArgs::default(), Some(&cfg)).unwrap();
    assert!(resolved.interactive);
    assert!(resolved.to_common_args().interactive);
}

#[test]
fn test_prompt_conflict_resolution_diff_then_choices() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("source.txt");
    let tgt = dir.path().join("target.txt");
    fs::write(&src, "new line\n").unwrap();
    fs::write(&tgt, "old line\n").unwrap();

    let action = FileAction::Symlink {
        source: src,
        target: tgt,
    };

    // 1. Invalid input -> 'd' (diff) -> 'o' (overwrite)
    let mut input = Cursor::new(b"invalid\nd\no\n");
    let mut output = Vec::new();
    let res = prompt_conflict_resolution(&action, None, &mut input, &mut output, false).unwrap();
    assert_eq!(res, ConflictResolution::Overwrite);
    let out_str = String::from_utf8(output).unwrap();
    assert!(out_str.contains("Invalid choice"));
    assert!(out_str.contains("-new line"));
    assert!(out_str.contains("+old line"));

    // 2. 'a' (adopt)
    let mut input_a = Cursor::new(b"a\n");
    let mut output_a = Vec::new();
    let res_a =
        prompt_conflict_resolution(&action, None, &mut input_a, &mut output_a, false).unwrap();
    assert_eq!(res_a, ConflictResolution::Adopt);

    // 3. 's' (skip) and EOF fallback
    let mut input_s = Cursor::new(b"s\n");
    let mut output_s = Vec::new();
    let res_s =
        prompt_conflict_resolution(&action, None, &mut input_s, &mut output_s, false).unwrap();
    assert_eq!(res_s, ConflictResolution::Skip);

    let mut input_eof = Cursor::new(b"");
    let mut output_eof = Vec::new();
    let res_eof =
        prompt_conflict_resolution(&action, None, &mut input_eof, &mut output_eof, false).unwrap();
    assert_eq!(res_eof, ConflictResolution::Skip);
}

#[test]
fn test_interactive_apply_symlink_overwrite_adopt_skip() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let pkg_dir = source_dir.path().join("pkg");
    fs::create_dir_all(&pkg_dir).unwrap();

    // 3 conflicting files in package
    let src_overwrite = pkg_dir.join("a_overwrite.conf");
    let src_adopt = pkg_dir.join("b_adopt.conf");
    let src_skip = pkg_dir.join("c_skip.conf");
    fs::write(&src_overwrite, "pkg overwrite\n").unwrap();
    fs::write(&src_adopt, "pkg adopt\n").unwrap();
    fs::write(&src_skip, "pkg skip\n").unwrap();

    // Pre-existing target files with local drift
    let tgt_overwrite = target_dir.path().join("a_overwrite.conf");
    let tgt_adopt = target_dir.path().join("b_adopt.conf");
    let tgt_skip = target_dir.path().join("c_skip.conf");
    fs::write(&tgt_overwrite, "local overwrite\n").unwrap();
    fs::write(&tgt_adopt, "local adopt\n").unwrap();
    fs::write(&tgt_skip, "local skip\n").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        packages: vec!["pkg".to_string()],
        interactive: true,
        ..Default::default()
    };

    let mut actions = plan_stow(&args).unwrap();
    actions.sort_by(|a, b| a.target().cmp(b.target()));
    assert_eq!(actions.len(), 3);

    // Scripted user responses:
    // 1st file (a_overwrite.conf): diff ('d'), then overwrite ('o')
    // 2nd file (b_adopt.conf): adopt ('a')
    // 3rd file (c_skip.conf): skip ('s')
    let mut input = Cursor::new(b"d\no\na\ns\n");
    let mut output = Vec::new();

    execute_plan_interactive_with_io(
        &actions,
        false,
        None,
        false,
        false,
        None,
        Some(target_dir.path()),
        None,
        false,
        true,
        &mut input,
        &mut output,
        false,
    )
    .unwrap();

    // 1. a_overwrite.conf was overwritten with symlink to pkg source
    assert!(is_symlink_to(&tgt_overwrite, &src_overwrite));
    assert_eq!(
        fs::read_to_string(&tgt_overwrite).unwrap(),
        "pkg overwrite\n"
    );

    // 2. b_adopt.conf was adopted into pkg source and linked
    assert!(is_symlink_to(&tgt_adopt, &src_adopt));
    assert_eq!(fs::read_to_string(&src_adopt).unwrap(), "local adopt\n");

    // 3. c_skip.conf was left untouched as regular local file
    let skip_meta = fs::symlink_metadata(&tgt_skip).unwrap();
    assert!(!skip_meta.file_type().is_symlink());
    assert_eq!(fs::read_to_string(&tgt_skip).unwrap(), "local skip\n");
}

#[test]
fn test_interactive_apply_secret_drift_resolution() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();
    let key_dir = tempdir().unwrap();

    let key_file = key_dir.path().join("key.txt");
    let key = age::x25519::Identity::generate();
    let pubkey = key.to_public();
    fs::write(&key_file, key.to_string().expose_secret()).unwrap();

    let pkg_dir = source_dir.path().join("secrets");
    fs::create_dir_all(&pkg_dir).unwrap();

    let encrypt_bytes = |data: &[u8]| -> Vec<u8> {
        let recipient: &dyn Recipient = &pubkey;
        let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient)).unwrap();
        let mut buf = Vec::new();
        let mut writer = encryptor.wrap_output(&mut buf).unwrap();
        writer.write_all(data).unwrap();
        writer.finish().unwrap();
        buf
    };

    // 1. synced.env.age (already matches target -> should NOT prompt)
    let src_synced = pkg_dir.join("1_synced.env.age");
    fs::write(&src_synced, encrypt_bytes(b"SYNCED=1\n")).unwrap();
    fs::write(target_dir.path().join("1_synced.env"), b"SYNCED=1\n").unwrap();

    // 2. overwrite.env.age (drifted -> user selects 'o')
    let src_overwrite = pkg_dir.join("2_overwrite.env.age");
    fs::write(&src_overwrite, encrypt_bytes(b"SECRET=from_pkg\n")).unwrap();
    let tgt_overwrite = target_dir.path().join("2_overwrite.env");
    fs::write(&tgt_overwrite, b"SECRET=local_drift\n").unwrap();

    // 3. adopt.env.age (drifted -> user selects 'a')
    let src_adopt = pkg_dir.join("3_adopt.env.age");
    fs::write(&src_adopt, encrypt_bytes(b"ADOPT=old_pkg\n")).unwrap();
    let tgt_adopt = target_dir.path().join("3_adopt.env");
    fs::write(&tgt_adopt, b"ADOPT=new_local\n").unwrap();

    // 4. skip.env.age (drifted -> user selects 's')
    let src_skip = pkg_dir.join("4_skip.env.age");
    fs::write(&src_skip, encrypt_bytes(b"SKIP=from_pkg\n")).unwrap();
    let tgt_skip = target_dir.path().join("4_skip.env");
    fs::write(&tgt_skip, b"SKIP=keep_local\n").unwrap();

    let args = CommonArgs {
        source: Some(source_dir.path().to_path_buf()),
        target: Some(target_dir.path().to_path_buf()),
        age_key_file: Some(key_file.clone()),
        packages: vec!["secrets".to_string()],
        interactive: true,
        ..Default::default()
    };

    let mut actions = plan_stow(&args).unwrap();
    actions.sort_by(|a, b| a.target().cmp(b.target()));
    assert_eq!(actions.len(), 4);

    // Only 3 prompts expected (1_synced.env is already in sync):
    // 'o' for 2_overwrite.env, 'a' for 3_adopt.env, 's' for 4_skip.env
    let mut input = Cursor::new(b"o\na\ns\n");
    let mut output = Vec::new();

    execute_plan_interactive_with_io(
        &actions,
        false,
        Some(&key_file),
        false,
        false,
        None,
        Some(target_dir.path()),
        None,
        false,
        true,
        &mut input,
        &mut output,
        false,
    )
    .unwrap();

    // 2_overwrite.env replaced with decrypted package secret
    assert_eq!(
        fs::read_to_string(&tgt_overwrite).unwrap(),
        "SECRET=from_pkg\n"
    );

    // 3_adopt.env re-encrypted into src_adopt
    let decrypted_adopted = enstow::crypto::decrypt_to_memory(
        &src_adopt,
        enstow::crypto::SecretType::Age,
        Some(&key_file),
    )
    .unwrap();
    assert_eq!(decrypted_adopted, b"ADOPT=new_local\n");

    // 4_skip.env untouched
    assert_eq!(fs::read_to_string(&tgt_skip).unwrap(), "SKIP=keep_local\n");
}
