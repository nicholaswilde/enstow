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
