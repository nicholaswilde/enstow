use std::path::Path;
use std::sync::Arc;

use self_update::http_client::HttpClient;
use self_update::update::{ReleaseAsset, ReleaseStatus};
use tracing::debug;

use crate::cli::SelfUpdateArgs;
use crate::error::EnstowError;

pub const REPO_OWNER: &str = "nicholaswilde";
pub const REPO_NAME: &str = "enstow";
pub const BIN_NAME: &str = "enstow";
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Outcome of executing a self-update check or installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    UpToDate { current: String },
    UpdateAvailable { current: String, latest: String },
    Updated { from: String, to: String },
    Cancelled { current: String, target: String },
}

/// Configuration options for running a self-update, allowing injection in tests.
pub struct UpdateOptions<'a> {
    pub current_version: &'a str,
    pub target: &'a str,
    pub quiet: bool,
    pub bin_install_path: Option<&'a Path>,
    pub http_client: Option<Arc<dyn HttpClient>>,
}

/// Map a Rust target triple to the corresponding release archive target published by CI.
pub fn release_target(target: &str) -> &str {
    match target {
        "x86_64-unknown-linux-gnu" => "x86_64-unknown-linux-musl",
        "aarch64-unknown-linux-gnu" => "aarch64-unknown-linux-musl",
        "armv7-unknown-linux-gnueabihf" => "armv7-unknown-linux-musleabihf",
        "arm-unknown-linux-gnueabi" | "arm-unknown-linux-gnueabihf" => "arm-unknown-linux-musleabi",
        "x86_64-pc-windows-gnu" => "x86_64-pc-windows-msvc",
        "i686-pc-windows-gnu" => "i686-pc-windows-msvc",
        other => other,
    }
}

/// Select the archive extension identifier matching the release asset for `target`.
pub fn archive_identifier_for_target(target: &str) -> &'static str {
    if target.contains("windows") {
        ".zip"
    } else {
        ".tar.gz"
    }
}

/// Normalize a user-supplied version string into `(tag_with_v, bare_version)`.
pub fn normalize_version_tag(version: &str) -> Result<(String, String), EnstowError> {
    let trimmed = version.trim();
    let bare = trimmed.trim_start_matches(['v', 'V']);
    if bare.is_empty()
        || !bare.chars().next().is_some_and(|c| c.is_ascii_digit())
        || bare.contains('/')
        || bare.contains('\\')
        || bare.contains("..")
        || bare.chars().any(char::is_whitespace)
    {
        return Err(EnstowError::Config(format!(
            "Invalid release version '{version}'"
        )));
    }
    Ok((format!("v{bare}"), bare.to_string()))
}

/// Return `true` when the resolved log level suppresses normal informational output.
pub fn is_quiet_log_level(log_level: &str) -> bool {
    matches!(
        log_level.trim().to_ascii_lowercase().as_str(),
        "warn" | "error" | "off"
    )
}

/// Execute `enstow self-update` against GitHub Releases for `nicholaswilde/enstow`.
pub fn run_self_update(
    args: &SelfUpdateArgs,
    log_level: &str,
) -> Result<UpdateOutcome, EnstowError> {
    run_self_update_with_options(
        args,
        UpdateOptions {
            current_version: CURRENT_VERSION,
            target: self_update::get_target(),
            quiet: is_quiet_log_level(log_level),
            bin_install_path: None,
            http_client: None,
        },
    )
}

/// Execute `self-update` with explicit target, version, and transport options.
pub fn run_self_update_with_options(
    args: &SelfUpdateArgs,
    opts: UpdateOptions<'_>,
) -> Result<UpdateOutcome, EnstowError> {
    let resolved_target = release_target(opts.target);
    let identifier = archive_identifier_for_target(resolved_target);
    let requested = args
        .version
        .as_deref()
        .map(normalize_version_tag)
        .transpose()?;

    debug!(
        current_version = opts.current_version,
        host_target = opts.target,
        release_target = resolved_target,
        archive_identifier = identifier,
        check_only = args.check,
        quiet = opts.quiet,
        "Preparing self-update"
    );

    if let Some((_, ref bare)) = requested {
        if bare == opts.current_version {
            debug!("Requested version matches current version; skipping network call");
            return Ok(UpdateOutcome::UpToDate {
                current: opts.current_version.to_string(),
            });
        }
    }

    let mut builder = self_update::backends::github::Update::configure();
    let match_target = resolved_target.to_string();
    builder
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name(BIN_NAME)
        .bin_path_in_archive("enstow-{{ version }}-{{ target }}/{{ bin }}")
        .current_version(opts.current_version)
        .target(resolved_target)
        .asset_identifier(identifier)
        .asset_matcher(move |assets| match_release_asset(assets, &match_target, identifier))
        .auth_token_from_env()
        .show_output(!opts.quiet)
        .show_download_progress(!opts.quiet)
        .no_confirm(args.yes)
        .check_install_path_writable(true);

    if let Some((ref tag, _)) = requested {
        builder.release_tag(tag);
    }
    if let Some(path) = opts.bin_install_path {
        builder.bin_install_path(path);
    }
    if let Some(client) = opts.http_client {
        builder.http_client(client);
    }

    let updater = builder
        .build()
        .map_err(|e| EnstowError::Update(e.to_string()))?;

    if args.check {
        return check_for_update(
            &updater,
            opts.current_version,
            resolved_target,
            identifier,
            requested.as_ref(),
        );
    }

    match updater.update_extended() {
        Ok(ReleaseStatus::UpToDate) => Ok(UpdateOutcome::UpToDate {
            current: opts.current_version.to_string(),
        }),
        Ok(ReleaseStatus::Updated(release)) => Ok(UpdateOutcome::Updated {
            from: opts.current_version.to_string(),
            to: release.version().to_string(),
        }),
        Ok(other) => Ok(match other.version() {
            Some(version) => UpdateOutcome::Updated {
                from: opts.current_version.to_string(),
                to: version.to_string(),
            },
            None => UpdateOutcome::UpToDate {
                current: opts.current_version.to_string(),
            },
        }),
        Err(self_update::errors::Error::Aborted) => Ok(UpdateOutcome::Cancelled {
            current: opts.current_version.to_string(),
            target: requested
                .map(|(tag, _)| tag)
                .unwrap_or_else(|| "latest".to_string()),
        }),
        Err(e) => Err(EnstowError::Update(e.to_string())),
    }
}

fn check_for_update(
    updater: &dyn self_update::update::ReleaseUpdate,
    current_version: &str,
    target: &str,
    identifier: &str,
    requested: Option<&(String, String)>,
) -> Result<UpdateOutcome, EnstowError> {
    let release = match requested {
        Some((tag, _)) => {
            debug!(tag = %tag, "Checking specific release tag");
            updater
                .get_release_version(tag)
                .map_err(|e| EnstowError::Update(e.to_string()))?
        }
        None => {
            debug!("Checking latest GitHub release");
            let releases = updater
                .get_latest_release()
                .map_err(|e| EnstowError::Update(e.to_string()))?;
            let latest = releases
                .latest()
                .ok_or_else(|| EnstowError::Update("No releases found".to_string()))?
                .clone();
            let is_newer = self_update::version::bump_is_greater(current_version, latest.version())
                .map_err(|e| EnstowError::Update(e.to_string()))?;
            if !is_newer {
                return Ok(UpdateOutcome::UpToDate {
                    current: current_version.to_string(),
                });
            }
            latest
        }
    };

    if match_release_asset(release.assets(), target, identifier).is_none() {
        return Err(EnstowError::Update(format!(
            "No release asset found for target '{target}' in v{}",
            release.version()
        )));
    }

    Ok(UpdateOutcome::UpdateAvailable {
        current: current_version.to_string(),
        latest: release.version().to_string(),
    })
}

fn match_release_asset(
    assets: &[ReleaseAsset],
    target: &str,
    identifier: &str,
) -> Option<ReleaseAsset> {
    assets
        .iter()
        .find(|asset| asset.name().contains(target) && asset.name().ends_with(identifier))
        .cloned()
}
