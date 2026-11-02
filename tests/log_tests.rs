use clap::Parser;
use enstow::cli::Cli;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn test_cli_parsing_log_flags() {
    let cli = Cli::try_parse_from(["enstow", "--log-level", "debug"]).unwrap();
    assert_eq!(cli.log_level.as_deref(), Some("debug"));
    assert_eq!(cli.verbose, 0);
    assert_eq!(cli.quiet, 0);

    let cli_v = Cli::try_parse_from(["enstow", "-v"]).unwrap();
    assert_eq!(cli_v.verbose, 1);
    assert_eq!(cli_v.quiet, 0);

    let cli_vv = Cli::try_parse_from(["enstow", "-vv"]).unwrap();
    assert_eq!(cli_vv.verbose, 2);

    let cli_verbose = Cli::try_parse_from(["enstow", "--verbose"]).unwrap();
    assert_eq!(cli_verbose.verbose, 1);

    let cli_q = Cli::try_parse_from(["enstow", "-q"]).unwrap();
    assert_eq!(cli_q.quiet, 1);
    assert_eq!(cli_q.verbose, 0);

    let cli_qq = Cli::try_parse_from(["enstow", "-qq"]).unwrap();
    assert_eq!(cli_qq.quiet, 2);

    let cli_quiet = Cli::try_parse_from(["enstow", "--quiet"]).unwrap();
    assert_eq!(cli_quiet.quiet, 1);

    // Global flags work before or after subcommands
    let cli_sub = Cli::try_parse_from(["enstow", "status", "--log-level", "warn"]).unwrap();
    assert_eq!(cli_sub.log_level.as_deref(), Some("warn"));

    let cli_sub_v = Cli::try_parse_from(["enstow", "-v", "status"]).unwrap();
    assert_eq!(cli_sub_v.verbose, 1);

    // Verbose and quiet conflict
    assert!(Cli::try_parse_from(["enstow", "-v", "-q"]).is_err());
}

#[test]
fn test_cli_log_level_execution_end_to_end() {
    let bin = env!("CARGO_BIN_EXE_enstow");
    let src = tempdir().unwrap();
    let tgt = tempdir().unwrap();

    // Create a dotfile in src so stow has actions to log
    let dotfile = src.path().join(".testrc");
    fs::write(&dotfile, "hello=world\n").unwrap();

    // 1. Verbose (-v) displays DEBUG log output
    let output = Command::new(bin)
        .args([
            "-v",
            "--source",
            src.path().to_str().unwrap(),
            "--target",
            tgt.path().to_str().unwrap(),
            "apply",
            "-n",
        ])
        .output()
        .expect("failed to run enstow");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("DEBUG"),
        "Expected DEBUG in stderr with -v, got:\n{}",
        stderr
    );

    // 2. Explicit --log-level debug displays DEBUG log output
    let output = Command::new(bin)
        .args([
            "--log-level",
            "debug",
            "--source",
            src.path().to_str().unwrap(),
            "--target",
            tgt.path().to_str().unwrap(),
            "apply",
            "-n",
        ])
        .output()
        .expect("failed to run enstow");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("DEBUG"),
        "Expected DEBUG in stderr with --log-level debug, got:\n{}",
        stderr
    );

    // 3. --log-level warn suppresses INFO and DEBUG output
    let output = Command::new(bin)
        .args([
            "--log-level",
            "warn",
            "--source",
            src.path().to_str().unwrap(),
            "--target",
            tgt.path().to_str().unwrap(),
            "apply",
            "-n",
        ])
        .output()
        .expect("failed to run enstow");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("DEBUG") && !stderr.contains("INFO"),
        "Expected no DEBUG or INFO in stderr with --log-level warn, got:\n{}",
        stderr
    );

    // 4. ENSTOW_LOG_LEVEL=error suppresses INFO and DEBUG output
    let output = Command::new(bin)
        .env("ENSTOW_LOG_LEVEL", "error")
        .args([
            "--source",
            src.path().to_str().unwrap(),
            "--target",
            tgt.path().to_str().unwrap(),
            "apply",
            "-n",
        ])
        .output()
        .expect("failed to run enstow");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("DEBUG") && !stderr.contains("INFO"),
        "Expected no DEBUG or INFO in stderr with ENSTOW_LOG_LEVEL=error, got:\n{}",
        stderr
    );

    // 5. Fallback to RUST_LOG operates when ENSTOW_LOG_LEVEL is not specified
    let output = Command::new(bin)
        .env_remove("ENSTOW_LOG_LEVEL")
        .env("RUST_LOG", "debug")
        .args([
            "--source",
            src.path().to_str().unwrap(),
            "--target",
            tgt.path().to_str().unwrap(),
            "apply",
            "-n",
        ])
        .output()
        .expect("failed to run enstow");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("DEBUG"),
        "Expected DEBUG in stderr with RUST_LOG=debug fallback, got:\n{}",
        stderr
    );

    // 6. ENSTOW_LOG_LEVEL takes precedence over RUST_LOG
    let output = Command::new(bin)
        .env("ENSTOW_LOG_LEVEL", "error")
        .env("RUST_LOG", "debug")
        .args([
            "--source",
            src.path().to_str().unwrap(),
            "--target",
            tgt.path().to_str().unwrap(),
            "apply",
            "-n",
        ])
        .output()
        .expect("failed to run enstow");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("DEBUG") && !stderr.contains("INFO"),
        "Expected ENSTOW_LOG_LEVEL=error to override RUST_LOG=debug, got:\n{}",
        stderr
    );

    // 7. Config file log_level = "warn" suppresses INFO when no CLI or env set
    let config_file = src.path().join("config.toml");
    fs::write(&config_file, "log_level = \"warn\"\n").unwrap();
    let output = Command::new(bin)
        .env_remove("ENSTOW_LOG_LEVEL")
        .env_remove("RUST_LOG")
        .args([
            "-C",
            config_file.to_str().unwrap(),
            "--source",
            src.path().to_str().unwrap(),
            "--target",
            tgt.path().to_str().unwrap(),
            "apply",
            "-n",
        ])
        .output()
        .expect("failed to run enstow");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("DEBUG") && !stderr.contains("INFO"),
        "Expected config log_level=\"warn\" to suppress INFO, got:\n{}",
        stderr
    );
}
