use clap::Parser;
use clap_complete::Shell;
use enstow::cli::{
    generate_completions, generate_dynamic_completions, generate_static_completions, Cli, Commands,
};

#[test]
fn test_cli_parse_completions_all_shells() {
    let shells = [
        ("bash", Shell::Bash),
        ("zsh", Shell::Zsh),
        ("fish", Shell::Fish),
        ("powershell", Shell::PowerShell),
        ("elvish", Shell::Elvish),
    ];

    for (shell_str, expected) in shells {
        let cli = Cli::try_parse_from(["enstow", "completions", shell_str]).unwrap();
        match cli.command {
            Some(Commands::Completions {
                shell,
                static_completions,
            }) => {
                assert_eq!(shell, expected);
                assert!(!static_completions);
            }
            other => panic!("Expected Commands::Completions, got {:?}", other),
        }
    }
}

#[test]
fn test_cli_parse_completions_static_flag() {
    let cli = Cli::try_parse_from(["enstow", "completions", "bash", "--static"]).unwrap();
    match cli.command {
        Some(Commands::Completions {
            shell,
            static_completions,
        }) => {
            assert_eq!(shell, Shell::Bash);
            assert!(static_completions);
        }
        other => panic!("Expected Commands::Completions, got {:?}", other),
    }
}

#[test]
fn test_generate_dynamic_completions_all_shells() {
    let shells = [
        (Shell::Bash, "_clap_complete_enstow"),
        (Shell::Zsh, "_clap_dynamic_completer_enstow"),
        (Shell::Fish, "COMPLETE=fish"),
        (Shell::PowerShell, "Register-ArgumentCompleter"),
        (Shell::Elvish, "edit:completion:arg-completer"),
    ];

    for (shell, expected_snippet) in shells {
        let mut buf = Vec::new();
        assert!(generate_dynamic_completions(shell, &mut buf).is_ok());
        let out = String::from_utf8(buf).expect("valid utf-8 dynamic completion script");
        assert!(
            out.contains(expected_snippet),
            "Dynamic shell {shell:?} missing snippet {expected_snippet}"
        );
    }
}

#[test]
fn test_generate_static_completions_all_shells() {
    let shells = [
        (Shell::Bash, "complete -F _enstow"),
        (Shell::Zsh, "_enstow"),
        (Shell::Fish, "complete -c enstow"),
        (Shell::PowerShell, "Register-ArgumentCompleter"),
        (Shell::Elvish, "edit:completion:arg-completer[enstow]"),
    ];

    for (shell, expected_snippet) in shells {
        let mut buf = Vec::new();
        generate_static_completions(shell, &mut buf);
        let out = String::from_utf8(buf).expect("valid utf-8 static completion script");
        assert!(
            out.contains(expected_snippet),
            "Static shell {shell:?} missing snippet {expected_snippet}"
        );
        assert!(
            out.contains("apply"),
            "Static shell {shell:?} should mention subcommand 'apply'"
        );
    }
}

#[test]
fn test_generate_completions_default_is_dynamic() {
    let mut buf = Vec::new();
    generate_completions(Shell::Bash, &mut buf);
    let out = String::from_utf8(buf).expect("valid utf-8 completion script");
    assert!(out.contains("_clap_complete_enstow"));
    assert!(out.contains("complete -o nospace -o bashdefault"));
}
