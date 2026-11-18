use std::collections::HashMap;
use std::fs;
use std::io::Cursor;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use enstow::cli::SelfUpdateArgs;
use enstow::update::{
    archive_identifier_for_target, is_quiet_log_level, normalize_version_tag, release_target,
    run_self_update_with_options, UpdateOptions, UpdateOutcome,
};
use self_update::http_client::{HeaderMap, HttpClient, HttpResponse};
use tempfile::tempdir;

struct MockResponse {
    headers: HeaderMap,
    body: Vec<u8>,
}

impl HttpResponse for MockResponse {
    fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    fn body(self: Box<Self>) -> Box<dyn std::io::Read> {
        Box::new(Cursor::new(self.body))
    }
}

struct MockHttpClient {
    routes: HashMap<String, Vec<u8>>,
    requested_urls: Mutex<Vec<String>>,
}

impl MockHttpClient {
    fn new(routes: Vec<(&str, Vec<u8>)>) -> Self {
        Self {
            routes: routes
                .into_iter()
                .map(|(u, b)| (u.to_string(), b))
                .collect(),
            requested_urls: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<String> {
        self.requested_urls.lock().unwrap().clone()
    }
}

impl HttpClient for MockHttpClient {
    fn get(
        &self,
        url: &str,
        _headers: &HeaderMap,
        _timeout: Option<Duration>,
    ) -> self_update::Result<Box<dyn HttpResponse>> {
        self.requested_urls.lock().unwrap().push(url.to_string());
        if let Some(body) = self.routes.get(url) {
            Ok(Box::new(MockResponse {
                headers: HeaderMap::new(),
                body: body.clone(),
            }))
        } else {
            Err(self_update::errors::Error::http_status_error(404, url))
        }
    }
}

fn release_json(version: &str, target: &str) -> String {
    let ext = if target.contains("windows") {
        "zip"
    } else {
        "tar.gz"
    };
    let archive_name = format!("enstow-{version}-{target}.{ext}");
    let sha_name = format!("{archive_name}.sha256");
    let download_url = format!("https://example.test/download/v{version}/{archive_name}");
    let sha_url = format!("https://example.test/download/v{version}/{sha_name}");
    // Put .sha256 and .deb before the archive to verify asset_identifier selects only the archive
    serde_json::json!({
        "tag_name": format!("v{version}"),
        "created_at": "2026-01-01T00:00:00Z",
        "name": version,
        "body": "Release notes",
        "html_url": format!("https://github.com/nicholaswilde/enstow/releases/tag/v{version}"),
        "assets": [
            { "name": sha_name, "url": sha_url },
            { "name": format!("enstow_{version}-1_amd64.deb"), "url": "https://example.test/deb" },
            { "name": archive_name, "url": download_url }
        ]
    })
    .to_string()
}

#[test]
fn test_release_target_mapping() {
    assert_eq!(
        release_target("x86_64-unknown-linux-gnu"),
        "x86_64-unknown-linux-musl"
    );
    assert_eq!(
        release_target("aarch64-unknown-linux-gnu"),
        "aarch64-unknown-linux-musl"
    );
    assert_eq!(
        release_target("armv7-unknown-linux-gnueabihf"),
        "armv7-unknown-linux-musleabihf"
    );
    assert_eq!(
        release_target("arm-unknown-linux-gnueabi"),
        "arm-unknown-linux-musleabi"
    );
    assert_eq!(
        release_target("arm-unknown-linux-gnueabihf"),
        "arm-unknown-linux-musleabi"
    );
    assert_eq!(
        release_target("x86_64-pc-windows-gnu"),
        "x86_64-pc-windows-msvc"
    );
    assert_eq!(
        release_target("i686-pc-windows-gnu"),
        "i686-pc-windows-msvc"
    );
    assert_eq!(
        release_target("x86_64-unknown-linux-musl"),
        "x86_64-unknown-linux-musl"
    );
    assert_eq!(
        release_target("aarch64-apple-darwin"),
        "aarch64-apple-darwin"
    );
    assert_eq!(
        release_target("x86_64-pc-windows-msvc"),
        "x86_64-pc-windows-msvc"
    );
}

#[test]
fn test_archive_identifier_for_target() {
    assert_eq!(
        archive_identifier_for_target("x86_64-unknown-linux-musl"),
        ".tar.gz"
    );
    assert_eq!(
        archive_identifier_for_target("aarch64-apple-darwin"),
        ".tar.gz"
    );
    assert_eq!(
        archive_identifier_for_target("x86_64-pc-windows-msvc"),
        ".zip"
    );
    assert_eq!(
        archive_identifier_for_target("i686-pc-windows-msvc"),
        ".zip"
    );
}

#[test]
fn test_normalize_version_tag() {
    assert_eq!(
        normalize_version_tag("0.1.12").unwrap(),
        ("v0.1.12".to_string(), "0.1.12".to_string())
    );
    assert_eq!(
        normalize_version_tag("v0.1.12").unwrap(),
        ("v0.1.12".to_string(), "0.1.12".to_string())
    );
    assert_eq!(
        normalize_version_tag("  v1.2.3-rc.1  ").unwrap(),
        ("v1.2.3-rc.1".to_string(), "1.2.3-rc.1".to_string())
    );
    assert!(normalize_version_tag("").is_err());
    assert!(normalize_version_tag("v").is_err());
    assert!(normalize_version_tag("0.1.12/../evil").is_err());
    assert!(normalize_version_tag("abc").is_err());
}

#[test]
fn test_is_quiet_log_level() {
    assert!(is_quiet_log_level("warn"));
    assert!(is_quiet_log_level("error"));
    assert!(is_quiet_log_level("off"));
    assert!(is_quiet_log_level("WARN"));
    assert!(!is_quiet_log_level("info"));
    assert!(!is_quiet_log_level("debug"));
    assert!(!is_quiet_log_level("trace"));
}

#[test]
fn test_check_update_available() {
    let target = "x86_64-unknown-linux-musl";
    let latest_url = "https://api.github.com/repos/nicholaswilde/enstow/releases/latest";
    let client = Arc::new(MockHttpClient::new(vec![(
        latest_url,
        release_json("0.2.0", target).into_bytes(),
    )]));

    let args = SelfUpdateArgs {
        version: None,
        check: true,
        yes: false,
    };
    let outcome = run_self_update_with_options(
        &args,
        UpdateOptions {
            current_version: "0.1.12",
            target,
            quiet: true,
            bin_install_path: None,
            http_client: Some(client.clone()),
        },
    )
    .unwrap();

    assert_eq!(
        outcome,
        UpdateOutcome::UpdateAvailable {
            current: "0.1.12".to_string(),
            latest: "0.2.0".to_string(),
        }
    );
    assert_eq!(client.requests(), vec![latest_url.to_string()]);
}

#[test]
fn test_check_already_up_to_date() {
    let target = "x86_64-unknown-linux-musl";
    let latest_url = "https://api.github.com/repos/nicholaswilde/enstow/releases/latest";
    let client = Arc::new(MockHttpClient::new(vec![(
        latest_url,
        release_json("0.1.12", target).into_bytes(),
    )]));

    let args = SelfUpdateArgs {
        version: None,
        check: true,
        yes: false,
    };
    let outcome = run_self_update_with_options(
        &args,
        UpdateOptions {
            current_version: "0.1.12",
            target,
            quiet: true,
            bin_install_path: None,
            http_client: Some(client),
        },
    )
    .unwrap();

    assert_eq!(
        outcome,
        UpdateOutcome::UpToDate {
            current: "0.1.12".to_string(),
        }
    );
}

#[test]
fn test_specified_version_matching_current_exits_without_network() {
    let client = Arc::new(MockHttpClient::new(vec![]));
    let args = SelfUpdateArgs {
        version: Some("v0.1.12".to_string()),
        check: false,
        yes: true,
    };
    let outcome = run_self_update_with_options(
        &args,
        UpdateOptions {
            current_version: "0.1.12",
            target: "x86_64-unknown-linux-musl",
            quiet: true,
            bin_install_path: None,
            http_client: Some(client.clone()),
        },
    )
    .unwrap();

    assert_eq!(
        outcome,
        UpdateOutcome::UpToDate {
            current: "0.1.12".to_string(),
        }
    );
    assert!(client.requests().is_empty());
}

#[test]
fn test_check_specific_version_tag() {
    let target = "x86_64-unknown-linux-musl";
    let tag_url = "https://api.github.com/repos/nicholaswilde/enstow/releases/tags/v0.2.5";
    let client = Arc::new(MockHttpClient::new(vec![(
        tag_url,
        release_json("0.2.5", target).into_bytes(),
    )]));

    let args = SelfUpdateArgs {
        version: Some("0.2.5".to_string()),
        check: true,
        yes: false,
    };
    let outcome = run_self_update_with_options(
        &args,
        UpdateOptions {
            current_version: "0.1.12",
            target,
            quiet: true,
            bin_install_path: None,
            http_client: Some(client.clone()),
        },
    )
    .unwrap();

    assert_eq!(
        outcome,
        UpdateOutcome::UpdateAvailable {
            current: "0.1.12".to_string(),
            latest: "0.2.5".to_string(),
        }
    );
    assert_eq!(client.requests(), vec![tag_url.to_string()]);
}

#[test]
fn test_check_missing_target_asset_returns_error() {
    let latest_url = "https://api.github.com/repos/nicholaswilde/enstow/releases/latest";
    // Release only has macOS asset, but we check for Linux musl
    let client = Arc::new(MockHttpClient::new(vec![(
        latest_url,
        release_json("0.2.0", "aarch64-apple-darwin").into_bytes(),
    )]));

    let args = SelfUpdateArgs {
        version: None,
        check: true,
        yes: false,
    };
    let err = run_self_update_with_options(
        &args,
        UpdateOptions {
            current_version: "0.1.12",
            target: "x86_64-unknown-linux-musl",
            quiet: true,
            bin_install_path: None,
            http_client: Some(client),
        },
    )
    .unwrap_err();

    assert!(
        err.to_string().contains("x86_64-unknown-linux-musl"),
        "unexpected error: {err}"
    );
}

#[cfg(unix)]
#[test]
fn test_update_extracts_and_replaces_binary_from_tar_gz() {
    let dir = tempdir().unwrap();
    let target = "x86_64-unknown-linux-musl";
    let version = "0.2.0";
    let staging_name = format!("enstow-{version}-{target}");
    let staging_dir = dir.path().join(&staging_name);
    fs::create_dir_all(&staging_dir).unwrap();
    fs::write(staging_dir.join("enstow"), b"new-enstow-binary").unwrap();

    let archive_path = dir.path().join(format!("{staging_name}.tar.gz"));
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&archive_path)
        .arg("-C")
        .arg(dir.path())
        .arg(&staging_name)
        .status();
    let Ok(st) = status else {
        return;
    };
    assert!(st.success());
    let archive_bytes = fs::read(&archive_path).unwrap();

    let install_path = dir.path().join("installed_enstow");
    fs::write(&install_path, b"old-enstow-binary").unwrap();

    let releases_url = "https://api.github.com/repos/nicholaswilde/enstow/releases?per_page=100";
    let download_url =
        format!("https://example.test/download/v{version}/enstow-{version}-{target}.tar.gz");
    let list_json = format!("[{}]", release_json(version, target));
    let client = Arc::new(MockHttpClient::new(vec![
        (releases_url, list_json.into_bytes()),
        (download_url.as_str(), archive_bytes),
    ]));

    let args = SelfUpdateArgs {
        version: None,
        check: false,
        yes: true,
    };
    let outcome = run_self_update_with_options(
        &args,
        UpdateOptions {
            current_version: "0.1.12",
            target: "x86_64-unknown-linux-gnu",
            quiet: true,
            bin_install_path: Some(&install_path),
            http_client: Some(client),
        },
    )
    .unwrap();

    assert_eq!(
        outcome,
        UpdateOutcome::Updated {
            from: "0.1.12".to_string(),
            to: "0.2.0".to_string(),
        }
    );
    assert_eq!(fs::read(&install_path).unwrap(), b"new-enstow-binary");
}

#[test]
fn test_update_when_already_up_to_date_skips_download() {
    let target = "x86_64-unknown-linux-musl";
    let releases_url = "https://api.github.com/repos/nicholaswilde/enstow/releases?per_page=100";
    let list_json = format!("[{}]", release_json("0.1.12", target));
    let client = Arc::new(MockHttpClient::new(vec![(
        releases_url,
        list_json.into_bytes(),
    )]));

    let args = SelfUpdateArgs {
        version: None,
        check: false,
        yes: true,
    };
    let outcome = run_self_update_with_options(
        &args,
        UpdateOptions {
            current_version: "0.1.12",
            target,
            quiet: true,
            bin_install_path: None,
            http_client: Some(client.clone()),
        },
    )
    .unwrap();

    assert_eq!(
        outcome,
        UpdateOutcome::UpToDate {
            current: "0.1.12".to_string(),
        }
    );
    assert_eq!(client.requests(), vec![releases_url.to_string()]);
}

#[test]
fn test_root_version_flag_unaffected_and_subcommand_help_works() {
    let bin = env!("CARGO_BIN_EXE_enstow");

    // Verify target binary can be executed in the current environment
    // (skips cross-compilation runners where child processes cannot run without binfmt_misc)
    let ver_out = match Command::new(bin).arg("--version").output() {
        Ok(output) if output.status.success() => output,
        _ => {
            eprintln!(
                "Skipping end-to-end binary test: target binary cannot be executed in this environment"
            );
            return;
        }
    };
    let ver_stdout = String::from_utf8_lossy(&ver_out.stdout);
    assert!(ver_stdout.contains("enstow"));
    assert!(ver_stdout.contains(env!("CARGO_PKG_VERSION")));

    let help_out = Command::new(bin)
        .args(["self-update", "--help"])
        .output()
        .unwrap();
    assert!(help_out.status.success());
    let help_stdout = String::from_utf8_lossy(&help_out.stdout);
    assert!(help_stdout.contains("--version"));
    assert!(help_stdout.contains("--check"));
    assert!(help_stdout.contains("--yes"));
}
