use crate::config::ResolvedCommonArgs;
use crate::error::EnstowError;
use std::path::Path;
use std::process::Command;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookType {
    PreApply,
    PostApply,
    PreUnstow,
    PostUnstow,
}

impl HookType {
    pub fn as_str(&self) -> &'static str {
        match self {
            HookType::PreApply => "pre_apply",
            HookType::PostApply => "post_apply",
            HookType::PreUnstow => "pre_unstow",
            HookType::PostUnstow => "post_unstow",
        }
    }
}

pub struct HookContext<'a> {
    pub hook_type: HookType,
    pub package: Option<&'a str>,
    pub source: &'a Path,
    pub target: &'a Path,
    pub dry_run: bool,
    pub force: bool,
}

pub fn execute_hook(command: &str, ctx: &HookContext) -> Result<(), EnstowError> {
    if ctx.dry_run {
        println!("[dry-run] HOOK ({}) {}", ctx.hook_type.as_str(), command);
        return Ok(());
    }

    info!(
        "Executing {} hook: {} (package: {:?})",
        ctx.hook_type.as_str(),
        command,
        ctx.package
    );

    #[cfg(not(windows))]
    let mut cmd = Command::new("sh");
    #[cfg(not(windows))]
    cmd.arg("-c").arg(command);

    #[cfg(windows)]
    let mut cmd = {
        let comspec = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
        let mut c = Command::new(comspec);
        c.arg("/C").arg(command);
        c
    };

    if let Some(pkg) = ctx.package {
        cmd.env("ENSTOW_PACKAGE", pkg);
    } else {
        cmd.env("ENSTOW_PACKAGE", "");
    }
    cmd.env("ENSTOW_SOURCE", ctx.source);
    cmd.env("ENSTOW_TARGET", ctx.target);
    cmd.env("ENSTOW_HOOK_TYPE", ctx.hook_type.as_str());
    cmd.env("ENSTOW_DRY_RUN", if ctx.dry_run { "true" } else { "false" });
    cmd.env("ENSTOW_FORCE", if ctx.force { "true" } else { "false" });

    if ctx.source.is_dir() {
        cmd.current_dir(ctx.source);
    }

    let status = cmd.status().map_err(|e| EnstowError::Hook {
        hook_type: ctx.hook_type.as_str().to_string(),
        command: command.to_string(),
        status: format!("Failed to spawn process: {e}"),
    })?;

    if !status.success() {
        let status_desc = match status.code() {
            Some(code) => format!("exit code {code}"),
            None => "terminated by signal".to_string(),
        };

        if ctx.force
            && (ctx.hook_type == HookType::PreApply || ctx.hook_type == HookType::PreUnstow)
        {
            warn!(
                "{} hook '{}' failed with {}, continuing due to force",
                ctx.hook_type.as_str(),
                command,
                status_desc
            );
            return Ok(());
        }

        return Err(EnstowError::Hook {
            hook_type: ctx.hook_type.as_str().to_string(),
            command: command.to_string(),
            status: status_desc,
        });
    }

    Ok(())
}

pub fn execute_hooks(commands: &[String], ctx: &HookContext) -> Result<(), EnstowError> {
    for cmd in commands {
        execute_hook(cmd, ctx)?;
    }
    Ok(())
}

pub fn run_pre_apply_hooks(args: &ResolvedCommonArgs) -> Result<(), EnstowError> {
    if args.no_hooks {
        return Ok(());
    }

    // 1. Global pre-apply hooks
    let global_ctx = HookContext {
        hook_type: HookType::PreApply,
        package: None,
        source: &args.source,
        target: &args.target,
        dry_run: args.dry_run,
        force: args.force,
    };
    execute_hooks(&args.hooks.global.pre_apply, &global_ctx)?;

    // 2. Package-specific pre-apply hooks
    for pkg in &args.packages {
        if let Some(pkg_hooks) = args.hooks.packages.get(pkg) {
            let pkg_source = args.source.join(pkg);
            let pkg_ctx = HookContext {
                hook_type: HookType::PreApply,
                package: Some(pkg),
                source: &pkg_source,
                target: &args.target,
                dry_run: args.dry_run,
                force: args.force,
            };
            execute_hooks(&pkg_hooks.pre_apply, &pkg_ctx)?;
        }
    }

    Ok(())
}

pub fn run_post_apply_hooks(args: &ResolvedCommonArgs) -> Result<(), EnstowError> {
    if args.no_hooks {
        return Ok(());
    }

    // 1. Package-specific post-apply hooks
    for pkg in &args.packages {
        if let Some(pkg_hooks) = args.hooks.packages.get(pkg) {
            let pkg_source = args.source.join(pkg);
            let pkg_ctx = HookContext {
                hook_type: HookType::PostApply,
                package: Some(pkg),
                source: &pkg_source,
                target: &args.target,
                dry_run: args.dry_run,
                force: args.force,
            };
            execute_hooks(&pkg_hooks.post_apply, &pkg_ctx)?;
        }
    }

    // 2. Global post-apply hooks
    let global_ctx = HookContext {
        hook_type: HookType::PostApply,
        package: None,
        source: &args.source,
        target: &args.target,
        dry_run: args.dry_run,
        force: args.force,
    };
    execute_hooks(&args.hooks.global.post_apply, &global_ctx)?;

    Ok(())
}

pub fn run_pre_unstow_hooks(args: &ResolvedCommonArgs) -> Result<(), EnstowError> {
    if args.no_hooks {
        return Ok(());
    }

    // 1. Global pre-unstow hooks
    let global_ctx = HookContext {
        hook_type: HookType::PreUnstow,
        package: None,
        source: &args.source,
        target: &args.target,
        dry_run: args.dry_run,
        force: args.force,
    };
    execute_hooks(&args.hooks.global.pre_unstow, &global_ctx)?;

    // 2. Package-specific pre-unstow hooks
    for pkg in &args.packages {
        if let Some(pkg_hooks) = args.hooks.packages.get(pkg) {
            let pkg_source = args.source.join(pkg);
            let pkg_ctx = HookContext {
                hook_type: HookType::PreUnstow,
                package: Some(pkg),
                source: &pkg_source,
                target: &args.target,
                dry_run: args.dry_run,
                force: args.force,
            };
            execute_hooks(&pkg_hooks.pre_unstow, &pkg_ctx)?;
        }
    }

    Ok(())
}

pub fn run_post_unstow_hooks(args: &ResolvedCommonArgs) -> Result<(), EnstowError> {
    if args.no_hooks {
        return Ok(());
    }

    // 1. Package-specific post-unstow hooks
    for pkg in &args.packages {
        if let Some(pkg_hooks) = args.hooks.packages.get(pkg) {
            let pkg_source = args.source.join(pkg);
            let pkg_ctx = HookContext {
                hook_type: HookType::PostUnstow,
                package: Some(pkg),
                source: &pkg_source,
                target: &args.target,
                dry_run: args.dry_run,
                force: args.force,
            };
            execute_hooks(&pkg_hooks.post_unstow, &pkg_ctx)?;
        }
    }

    // 2. Global post-unstow hooks
    let global_ctx = HookContext {
        hook_type: HookType::PostUnstow,
        package: None,
        source: &args.source,
        target: &args.target,
        dry_run: args.dry_run,
        force: args.force,
    };
    execute_hooks(&args.hooks.global.post_unstow, &global_ctx)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResolvedHooks;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_hook_type_as_str() {
        assert_eq!(HookType::PreApply.as_str(), "pre_apply");
        assert_eq!(HookType::PostApply.as_str(), "post_apply");
        assert_eq!(HookType::PreUnstow.as_str(), "pre_unstow");
        assert_eq!(HookType::PostUnstow.as_str(), "post_unstow");
    }

    #[test]
    fn test_execute_hook_dry_run() {
        let dir = tempdir().unwrap();
        let ctx = HookContext {
            hook_type: HookType::PreApply,
            package: Some("pkg1"),
            source: dir.path(),
            target: dir.path(),
            dry_run: true,
            force: false,
        };
        // A command that would definitely fail if actually run
        let res = execute_hook("exit 42", &ctx);
        assert!(res.is_ok());
    }

    #[test]
    fn test_execute_hook_success() {
        let dir = tempdir().unwrap();
        let ctx = HookContext {
            hook_type: HookType::PreApply,
            package: Some("pkg1"),
            source: dir.path(),
            target: dir.path(),
            dry_run: false,
            force: false,
        };

        #[cfg(not(windows))]
        let cmd = "true";
        #[cfg(windows)]
        let cmd = "cd .";

        let res = execute_hook(cmd, &ctx);
        assert!(res.is_ok());
    }

    #[test]
    fn test_execute_hook_failure_and_force() {
        let dir = tempdir().unwrap();

        #[cfg(not(windows))]
        let fail_cmd = "exit 1";
        #[cfg(windows)]
        let fail_cmd = "cmd /C exit 1";

        // Without force: should return EnstowError::Hook
        let ctx_no_force = HookContext {
            hook_type: HookType::PreApply,
            package: None,
            source: dir.path(),
            target: dir.path(),
            dry_run: false,
            force: false,
        };
        let err = execute_hook(fail_cmd, &ctx_no_force).unwrap_err();
        match err {
            EnstowError::Hook {
                hook_type, status, ..
            } => {
                assert_eq!(hook_type, "pre_apply");
                assert!(status.contains("exit code 1"));
            }
            _ => panic!("Expected EnstowError::Hook, got {:?}", err),
        }

        // With force and PreApply: should succeed with a warning
        let ctx_force_pre = HookContext {
            hook_type: HookType::PreApply,
            package: None,
            source: dir.path(),
            target: dir.path(),
            dry_run: false,
            force: true,
        };
        assert!(execute_hook(fail_cmd, &ctx_force_pre).is_ok());

        // With force and PreUnstow: should succeed with a warning
        let ctx_force_unstow = HookContext {
            hook_type: HookType::PreUnstow,
            package: None,
            source: dir.path(),
            target: dir.path(),
            dry_run: false,
            force: true,
        };
        assert!(execute_hook(fail_cmd, &ctx_force_unstow).is_ok());

        // With force and PostApply: should still fail (force doesn't suppress post-apply)
        let ctx_force_post = HookContext {
            hook_type: HookType::PostApply,
            package: None,
            source: dir.path(),
            target: dir.path(),
            dry_run: false,
            force: true,
        };
        assert!(execute_hook(fail_cmd, &ctx_force_post).is_err());
    }

    #[test]
    fn test_execute_hooks_multiple() {
        let dir = tempdir().unwrap();
        let ctx = HookContext {
            hook_type: HookType::PreApply,
            package: None,
            source: dir.path(),
            target: dir.path(),
            dry_run: true,
            force: false,
        };
        let commands = vec!["echo 1".to_string(), "echo 2".to_string()];
        assert!(execute_hooks(&commands, &ctx).is_ok());
    }

    fn sample_args(dry_run: bool, no_hooks: bool) -> ResolvedCommonArgs {
        let mut packages = BTreeMap::new();
        let mut pkg_hooks = crate::config::HooksConfig::default();
        pkg_hooks.pre_apply.push("echo pkg_pre".to_string());
        pkg_hooks.post_apply.push("echo pkg_post".to_string());
        pkg_hooks.pre_unstow.push("echo pkg_pre_unstow".to_string());
        pkg_hooks
            .post_unstow
            .push("echo pkg_post_unstow".to_string());
        packages.insert("dot_pkg".to_string(), pkg_hooks);

        let mut global = crate::config::HooksConfig::default();
        global.pre_apply.push("echo global_pre".to_string());
        global.post_apply.push("echo global_post".to_string());
        global.pre_unstow.push("echo global_pre_unstow".to_string());
        global
            .post_unstow
            .push("echo global_post_unstow".to_string());

        ResolvedCommonArgs {
            source: PathBuf::from("/tmp/source"),
            target: PathBuf::from("/tmp/target"),
            dry_run,
            force: false,
            prune: false,
            age_key_file: None,
            profile: None,
            packages: vec!["dot_pkg".to_string()],
            ignore: Vec::new(),
            backup: false,
            backup_dir: PathBuf::from("/tmp/backup"),
            permissions: crate::config::PermissionsConfig::default(),
            adopt: false,
            no_hooks,
            hooks: ResolvedHooks { global, packages },
        }
    }

    #[test]
    fn test_run_hooks_no_hooks() {
        let args = sample_args(false, true);
        assert!(run_pre_apply_hooks(&args).is_ok());
        assert!(run_post_apply_hooks(&args).is_ok());
        assert!(run_pre_unstow_hooks(&args).is_ok());
        assert!(run_post_unstow_hooks(&args).is_ok());
    }

    #[test]
    fn test_run_hooks_execution_dry_run() {
        let args = sample_args(true, false);
        assert!(run_pre_apply_hooks(&args).is_ok());
        assert!(run_post_apply_hooks(&args).is_ok());
        assert!(run_pre_unstow_hooks(&args).is_ok());
        assert!(run_post_unstow_hooks(&args).is_ok());
    }
}
