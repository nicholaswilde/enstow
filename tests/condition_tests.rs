use enstow::cli::CommonArgs;
use enstow::config::{
    resolve_common_args, resolve_packages, resolve_packages_for_host, ConfigFile, ConfigFormat,
    HostInfo, PackageConfig, ProfileConfig,
};
use enstow::stow::{
    check_status, execute_plan, execute_unstow_plan, is_symlink_to, plan_stow, plan_unstow,
    EntryStatus,
};
use std::collections::BTreeMap;
use std::fs;
use tempfile::tempdir;

#[test]
fn test_config_deserialize_package_conditions_all_formats() {
    let toml_content = r#"
[package.macos]
os = "macos"
arch = ["aarch64", "x86_64"]
hostname = "macbook"

[package.linux_cluster]
os = ["linux", "freebsd"]
arch = "x86_64"
hostname = ["node1", "node2"]
"#;
    let cfg_toml = ConfigFile::parse(toml_content, ConfigFormat::Toml).unwrap();
    let pkgs = cfg_toml.package.as_ref().unwrap();

    let macos = pkgs.get("macos").unwrap();
    assert_eq!(macos.os, vec!["macos"]);
    assert_eq!(macos.arch, vec!["aarch64", "x86_64"]);
    assert_eq!(macos.hostname, vec!["macbook"]);

    let linux = pkgs.get("linux_cluster").unwrap();
    assert_eq!(linux.os, vec!["linux", "freebsd"]);
    assert_eq!(linux.arch, vec!["x86_64"]);
    assert_eq!(linux.hostname, vec!["node1", "node2"]);

    let yaml_content = r#"
package:
  workstation:
    os: linux
    arch:
      - x86_64
      - aarch64
    hostname: devbox
"#;
    let cfg_yaml = ConfigFile::parse(yaml_content, ConfigFormat::Yaml).unwrap();
    let ws = cfg_yaml
        .package
        .as_ref()
        .unwrap()
        .get("workstation")
        .unwrap();
    assert_eq!(ws.os, vec!["linux"]);
    assert_eq!(ws.arch, vec!["x86_64", "aarch64"]);
    assert_eq!(ws.hostname, vec!["devbox"]);

    let json_content = r#"{
        "package": {
            "win": {
                "os": "windows",
                "arch": "x86_64",
                "hostname": ["pc1", "pc2"]
            }
        }
    }"#;
    let cfg_json = ConfigFile::parse(json_content, ConfigFormat::Json).unwrap();
    let win = cfg_json.package.as_ref().unwrap().get("win").unwrap();
    assert_eq!(win.os, vec!["windows"]);
    assert_eq!(win.arch, vec!["x86_64"]);
    assert_eq!(win.hostname, vec!["pc1", "pc2"]);
}

#[test]
fn test_package_config_matches_host() {
    let linux_host = HostInfo {
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        hostname: "workstation.local".to_string(),
    };
    let mac_host = HostInfo {
        os: "macos".to_string(),
        arch: "aarch64".to_string(),
        hostname: "macbook".to_string(),
    };

    // Unconstrained package matches everything
    let empty_pkg = PackageConfig::default();
    assert!(empty_pkg.matches_host(&linux_host));
    assert!(empty_pkg.matches_host(&mac_host));

    // OS constraint (including case-insensitivity and darwin alias)
    let mac_pkg = PackageConfig {
        os: vec!["darwin".to_string()],
        ..Default::default()
    };
    assert!(!mac_pkg.matches_host(&linux_host));
    assert!(mac_pkg.matches_host(&mac_host));

    // Arch constraint (including arm64/amd64 aliases)
    let arm_pkg = PackageConfig {
        arch: vec!["arm64".to_string()],
        ..Default::default()
    };
    assert!(!arm_pkg.matches_host(&linux_host));
    assert!(arm_pkg.matches_host(&mac_host));

    // Hostname constraint (short name matches FQDN/.local)
    let host_pkg = PackageConfig {
        hostname: vec!["workstation".to_string()],
        ..Default::default()
    };
    assert!(host_pkg.matches_host(&linux_host));
    assert!(!host_pkg.matches_host(&mac_host));

    // Combined AND across fields, OR within fields
    let combined = PackageConfig {
        os: vec!["linux".to_string(), "macos".to_string()],
        arch: vec!["x86_64".to_string()],
        hostname: vec!["workstation".to_string(), "macbook".to_string()],
        ..Default::default()
    };
    assert!(combined.matches_host(&linux_host));
    assert!(!combined.matches_host(&mac_host)); // arch is aarch64 != x86_64
}

#[test]
fn test_resolve_packages_for_host_filtering() {
    let mut pkg_map = BTreeMap::new();
    pkg_map.insert(
        "linux_only".to_string(),
        PackageConfig {
            os: vec!["linux".to_string()],
            ..Default::default()
        },
    );
    pkg_map.insert(
        "macos_only".to_string(),
        PackageConfig {
            os: vec!["macos".to_string()],
            ..Default::default()
        },
    );
    pkg_map.insert(
        "arm_mac".to_string(),
        PackageConfig {
            os: vec!["macos".to_string()],
            arch: vec!["aarch64".to_string()],
            ..Default::default()
        },
    );
    pkg_map.insert(
        "server_host".to_string(),
        PackageConfig {
            hostname: vec!["prod-01".to_string()],
            ..Default::default()
        },
    );

    let mut profiles = BTreeMap::new();
    profiles.insert(
        "all".to_string(),
        ProfileConfig {
            packages: vec![
                "common".to_string(),
                "linux_only".to_string(),
                "macos_only".to_string(),
                "arm_mac".to_string(),
                "server_host".to_string(),
            ],
        },
    );

    let config = ConfigFile {
        profiles: Some(profiles),
        package: Some(pkg_map),
        ..Default::default()
    };

    let linux_host = HostInfo {
        os: "linux".to_string(),
        arch: "x86_64".to_string(),
        hostname: "dev-laptop".to_string(),
    };
    let resolved_linux =
        resolve_packages_for_host(&[], Some("all"), Some(&config), &linux_host).unwrap();
    assert_eq!(resolved_linux, vec!["common", "linux_only"]);

    let mac_arm_host = HostInfo {
        os: "macos".to_string(),
        arch: "aarch64".to_string(),
        hostname: "prod-01".to_string(),
    };
    let resolved_mac =
        resolve_packages_for_host(&[], Some("all"), Some(&config), &mac_arm_host).unwrap();
    assert_eq!(
        resolved_mac,
        vec!["common", "macos_only", "arm_mac", "server_host"]
    );
}

#[test]
fn test_apply_restow_unstow_status_skip_non_matching_packages() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    for pkg in [
        "common",
        "match_host",
        "wrong_os",
        "wrong_arch",
        "wrong_hostname",
    ] {
        let dir = source_dir.path().join(pkg);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join(format!(".{pkg}rc")), format!("# {pkg}\n")).unwrap();
    }

    let current = HostInfo::current();
    let toml_content = format!(
        r#"
packages = ["common", "match_host", "wrong_os", "wrong_arch", "wrong_hostname"]

[package.match_host]
os = "{}"
arch = "{}"

[package.wrong_os]
os = "nonexistent-os-xyz"

[package.wrong_arch]
arch = "nonexistent-arch-xyz"

[package.wrong_hostname]
hostname = "nonexistent-host-xyz-999"
"#,
        current.os, current.arch
    );

    let mut config = ConfigFile::parse(&toml_content, ConfigFormat::Toml).unwrap();
    config.source = Some(source_dir.path().to_path_buf());
    config.target = Some(target_dir.path().to_path_buf());

    let cli_args = CommonArgs::default();
    let resolved = resolve_common_args(&cli_args, Some(&config))
        .unwrap()
        .to_common_args();

    assert_eq!(resolved.packages, vec!["common", "match_host"]);
    assert_eq!(
        resolve_packages(&[], None, Some(&config)).unwrap(),
        vec!["common", "match_host"]
    );

    // 1. Apply
    let apply_plan = plan_stow(&resolved).unwrap();
    assert_eq!(apply_plan.len(), 2);
    execute_plan(&apply_plan, false, None, false).unwrap();

    assert!(is_symlink_to(
        &target_dir.path().join(".commonrc"),
        &source_dir.path().join("common").join(".commonrc")
    ));
    assert!(is_symlink_to(
        &target_dir.path().join(".match_hostrc"),
        &source_dir.path().join("match_host").join(".match_hostrc")
    ));
    assert!(fs::symlink_metadata(target_dir.path().join(".wrong_osrc")).is_err());
    assert!(fs::symlink_metadata(target_dir.path().join(".wrong_archrc")).is_err());
    assert!(fs::symlink_metadata(target_dir.path().join(".wrong_hostnamerc")).is_err());

    // 2. Status
    let statuses = check_status(&apply_plan, None).unwrap();
    assert_eq!(statuses.len(), 2);
    assert!(statuses.iter().all(|s| s.status == EntryStatus::Synced));

    // 3. Restow (unstow + apply)
    let unstow_plan = plan_unstow(&resolved).unwrap();
    execute_unstow_plan(&unstow_plan, target_dir.path(), false).unwrap();
    execute_plan(&apply_plan, false, None, false).unwrap();
    assert!(is_symlink_to(
        &target_dir.path().join(".commonrc"),
        &source_dir.path().join("common").join(".commonrc")
    ));

    // 4. Unstow
    execute_unstow_plan(&unstow_plan, target_dir.path(), false).unwrap();
    assert!(fs::symlink_metadata(target_dir.path().join(".commonrc")).is_err());
    assert!(fs::symlink_metadata(target_dir.path().join(".match_hostrc")).is_err());
}

#[test]
fn test_all_packages_filtered_out_does_not_stow_source_root() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let pkg_dir = source_dir.path().join("wrong_os");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(pkg_dir.join(".wrongrc"), "# wrong\n").unwrap();

    let toml_content = r#"
packages = ["wrong_os"]

[package.wrong_os]
os = "nonexistent-os-xyz"
"#;
    let mut config = ConfigFile::parse(toml_content, ConfigFormat::Toml).unwrap();
    config.source = Some(source_dir.path().to_path_buf());
    config.target = Some(target_dir.path().to_path_buf());

    let resolved = resolve_common_args(&CommonArgs::default(), Some(&config))
        .unwrap()
        .to_common_args();

    assert!(resolved.packages.is_empty());
    let actions = plan_stow(&resolved).unwrap();
    assert!(
        actions.is_empty(),
        "Expected 0 actions when all configured packages are filtered out, got {:?}",
        actions
    );
}

#[test]
fn test_implicit_root_scan_ignores_disabled_packages() {
    let source_dir = tempdir().unwrap();
    let target_dir = tempdir().unwrap();

    let wrong_dir = source_dir.path().join("wrong_os");
    fs::create_dir_all(&wrong_dir).unwrap();
    fs::write(wrong_dir.join(".wrongrc"), "# wrong\n").unwrap();
    fs::write(source_dir.path().join(".rootrc"), "# root\n").unwrap();

    let toml_content = r#"
[package.wrong_os]
os = "nonexistent-os-xyz"
"#;
    let mut config = ConfigFile::parse(toml_content, ConfigFormat::Toml).unwrap();
    config.source = Some(source_dir.path().to_path_buf());
    config.target = Some(target_dir.path().to_path_buf());

    let resolved = resolve_common_args(&CommonArgs::default(), Some(&config))
        .unwrap()
        .to_common_args();

    let actions = plan_stow(&resolved).unwrap();
    assert_eq!(actions.len(), 1);
    assert_eq!(actions[0].target(), target_dir.path().join(".rootrc"));
}
