use clap::Parser;
use enstow::cli::{generate_manpage, Cli, Commands};

#[test]
fn test_cli_parsing_man() {
    let cli = Cli::try_parse_from(["enstow", "man"]).unwrap();
    match cli.command {
        Some(Commands::Man) => {}
        other => panic!("Expected Commands::Man, got {:?}", other),
    }
}

#[test]
fn test_generate_manpage_renders_roff() {
    let mut man_buf = Vec::new();
    assert!(generate_manpage(&mut man_buf).is_ok());
    let man_str = String::from_utf8(man_buf).expect("valid utf-8 roff output");

    assert!(man_str.contains(".TH enstow 1"));
    assert!(man_str.contains(".SH NAME"));
    assert!(man_str.contains(".SH SYNOPSIS"));
    assert!(man_str.contains(".SH DESCRIPTION"));

    assert!(man_str.contains("apply"));
    assert!(man_str.contains("restow"));
    assert!(man_str.contains("unstow"));
    assert!(man_str.contains("encrypt"));
    assert!(man_str.contains("decrypt"));
    assert!(man_str.contains("edit"));
    assert!(man_str.contains("status"));
    assert!(man_str.contains("diff"));
    assert!(man_str.contains("man"));
    assert!(man_str.contains("completions"));
}
