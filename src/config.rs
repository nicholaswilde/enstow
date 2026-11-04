use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::{default_target_dir, CommonArgs};

/// Format of configuration files supported by `enstow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Toml,
    Yaml,
    Json,
}

impl ConfigFormat {
    pub fn from_path(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        match ext.as_str() {
            "toml" => Some(ConfigFormat::Toml),
            "yaml" | "yml" => Some(ConfigFormat::Yaml),
            "json" => Some(ConfigFormat::Json),
            _ => None,
        }
    }
}

/// Flexible representation of age recipient keys in configuration files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecipientsConfig {
    Single(String),
    List(Vec<String>),
}

impl RecipientsConfig {
    pub fn to_recipients(&self) -> Vec<String> {
        match self {
            Self::Single(s) => s
                .split([',', '\n'])
                .map(|token| token.trim().to_string())
                .filter(|token| !token.is_empty())
                .collect(),
            Self::List(list) => list
                .iter()
                .flat_map(|s| s.split([',', '\n']))
                .map(|token| token.trim().to_string())
                .filter(|token| !token.is_empty())
                .collect(),
        }
    }
}

/// Flexible representation of permission modes in configuration files (string octal or integer).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PermissionMode {
    Str(String),
    Int(u32),
}

impl PermissionMode {
    pub fn to_mode(&self) -> Result<u32> {
        match self {
            Self::Str(s) => parse_mode_str(s),
            Self::Int(n) => parse_mode_int(*n),
        }
    }
}

pub fn parse_mode_str(s: &str) -> Result<u32> {
    let clean = s.trim();
    let clean = clean.strip_prefix("0o").unwrap_or(clean);
    let octal_str = if clean.len() > 1 && clean.starts_with('0') {
        clean.trim_start_matches('0')
    } else {
        clean
    };
    let octal_str = if octal_str.is_empty() { "0" } else { octal_str };
    u32::from_str_radix(octal_str, 8)
        .with_context(|| format!("Invalid octal permission mode '{s}'"))
}

pub fn parse_mode_int(n: u32) -> Result<u32> {
    let s = n.to_string();
    if n > 0o777 && s.chars().all(|c| ('0'..='7').contains(&c)) {
        if let Ok(octal_val) = u32::from_str_radix(&s, 8) {
            return Ok(octal_val);
        }
    }
    if n <= 0o7777 {
        Ok(n)
    } else {
        anyhow::bail!("Permission mode {n} exceeds maximum unix mode 07777");
    }
}

/// Configuration for a specific dotfile package.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PackageConfig {
    #[serde(default)]
    pub permissions: BTreeMap<String, PermissionMode>,
}

/// Configuration for a package profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileConfig {
    #[serde(default)]
    pub packages: Vec<String>,
}

/// Representation of values loaded from a configuration file.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigFile {
    pub source: Option<PathBuf>,
    pub target: Option<PathBuf>,
    pub dry_run: Option<bool>,
    pub force: Option<bool>,
    pub prune: Option<bool>,
    pub adopt: Option<bool>,
    pub age_key_file: Option<PathBuf>,
    pub recipients: Option<RecipientsConfig>,
    pub packages: Option<Vec<String>>,
    pub editor: Option<String>,
    pub ignore: Option<Vec<String>>,
    pub json: Option<bool>,
    pub output: Option<String>,
    pub log_level: Option<String>,
    pub backup: Option<bool>,
    pub backup_dir: Option<PathBuf>,
    pub mask_secrets: Option<bool>,
    pub default_profile: Option<String>,
    pub profiles: Option<BTreeMap<String, ProfileConfig>>,
    pub permissions: Option<BTreeMap<String, PermissionMode>>,
    pub package: Option<BTreeMap<String, PackageConfig>>,
    pub package_permissions: Option<BTreeMap<String, BTreeMap<String, PermissionMode>>>,
}

impl ConfigFile {
    /// Parse configuration file content given a format.
    pub fn parse(content: &str, format: ConfigFormat) -> Result<Self> {
        match format {
            ConfigFormat::Toml => {
                toml::from_str(content).context("Failed to parse TOML configuration")
            }
            ConfigFormat::Yaml => {
                serde_yaml_ng::from_str(content).context("Failed to parse YAML configuration")
            }
            ConfigFormat::Json => {
                serde_json::from_str(content).context("Failed to parse JSON configuration")
            }
        }
    }

    /// Load and parse a configuration file from a specified path.
    pub fn load_from_path(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read configuration file '{}'", path.display()))?;

        let format = ConfigFormat::from_path(path).ok_or_else(|| {
            anyhow::anyhow!(
                "Unsupported configuration format for '{}'. Expected .toml, .yaml, .yml, or .json",
                path.display()
            )
        })?;

        Self::parse(&content, format)
    }

    /// Discover and load the default configuration file if present at standard paths.
    pub fn load_default() -> Result<Option<(PathBuf, Self)>> {
        for path in default_config_paths() {
            if path.is_file() {
                let cfg = Self::load_from_path(&path)?;
                return Ok(Some((path, cfg)));
            }
        }
        Ok(None)
    }
}

/// Standard candidate locations for default configuration files.
pub fn default_config_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    let config_dir = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            Some(PathBuf::from(xdg).join("enstow"))
        } else {
            None
        }
    } else {
        None
    };

    let config_dir = config_dir
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .filter(|h| !h.is_empty())
                .map(|h| PathBuf::from(h).join(".config").join("enstow"))
        })
        .or_else(|| {
            std::env::var("APPDATA")
                .ok()
                .filter(|a| !a.is_empty())
                .map(|a| PathBuf::from(a).join("enstow"))
        })
        .or_else(|| {
            std::env::var("USERPROFILE")
                .ok()
                .filter(|u| !u.is_empty())
                .map(|u| PathBuf::from(u).join(".config").join("enstow"))
        });

    if let Some(dir) = config_dir {
        paths.push(dir.join("config.toml"));
        paths.push(dir.join("config.yaml"));
        paths.push(dir.join("config.yml"));
        paths.push(dir.join("config.json"));
    }

    paths
}

/// Load configuration from explicit path, ENSTOW_CONFIG environment variable, or default paths.
pub fn load_config(explicit_path: Option<&Path>) -> Result<Option<(PathBuf, ConfigFile)>> {
    if let Some(path) = explicit_path {
        if path.is_file() {
            let cfg = ConfigFile::load_from_path(path)?;
            return Ok(Some((path.to_path_buf(), cfg)));
        } else if path.exists() {
            anyhow::bail!(
                "Configuration path '{}' is not a regular file",
                path.display()
            );
        } else {
            anyhow::bail!("Configuration file not found: {}", path.display());
        }
    }

    if let Ok(env_path) = std::env::var("ENSTOW_CONFIG") {
        if !env_path.trim().is_empty() {
            let p = Path::new(&env_path);
            if p.is_file() {
                let cfg = ConfigFile::load_from_path(p)?;
                return Ok(Some((p.to_path_buf(), cfg)));
            } else if p.exists() {
                anyhow::bail!(
                    "Configuration path '{}' from ENSTOW_CONFIG is not a regular file",
                    p.display()
                );
            } else {
                anyhow::bail!(
                    "Configuration file from ENSTOW_CONFIG not found: {}",
                    p.display()
                );
            }
        }
    }

    ConfigFile::load_default()
}

/// Compiled permission rules for setting target file modes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PermissionsConfig {
    pub rules: Vec<(String, u32, Option<String>)>,
}

impl PermissionsConfig {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn add_rule(&mut self, pattern: String, mode: u32, package: Option<String>) {
        self.rules.push((pattern, mode, package));
    }

    pub fn resolve_mode(
        &self,
        target: &Path,
        source: Option<&Path>,
        target_root: Option<&Path>,
    ) -> u32 {
        for (pattern, mode, package) in &self.rules {
            if let Some(pkg) = package {
                let matches_pkg = source
                    .is_some_and(|src| src.components().any(|c| c.as_os_str() == pkg.as_str()));
                if !matches_pkg {
                    continue;
                }
            }

            if let Ok(glob) = globset::GlobBuilder::new(pattern)
                .literal_separator(false)
                .backslash_escape(true)
                .build()
            {
                let matcher = glob.compile_matcher();
                if matcher.is_match(target) {
                    return *mode;
                }
                if let Some(root) = target_root {
                    if let Ok(rel) = target.strip_prefix(root) {
                        if matcher.is_match(rel) {
                            return *mode;
                        }
                    }
                }
                if let Some(file_name) = target.file_name() {
                    if matcher.is_match(Path::new(file_name)) {
                        return *mode;
                    }
                }
            }
        }
        0o600
    }
}

/// Fully resolved common arguments after evaluating the precedence chain:
/// 1. Command Line Arguments
/// 2. Environment Variables
/// 3. Configuration File
/// 4. Hardcoded Defaults
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCommonArgs {
    pub source: PathBuf,
    pub target: PathBuf,
    pub dry_run: bool,
    pub force: bool,
    pub prune: bool,
    pub age_key_file: Option<PathBuf>,
    pub profile: Option<String>,
    pub packages: Vec<String>,
    pub ignore: Vec<String>,
    pub backup: bool,
    pub backup_dir: PathBuf,
    pub permissions: PermissionsConfig,
    pub adopt: bool,
}

impl ResolvedCommonArgs {
    pub fn to_common_args(&self) -> CommonArgs {
        CommonArgs {
            source: Some(self.source.clone()),
            target: Some(self.target.clone()),
            dry_run: self.dry_run,
            force: self.force,
            prune: self.prune,
            age_key_file: self.age_key_file.clone(),
            profile: self.profile.clone(),
            packages: self.packages.clone(),
            ignore: self.ignore.clone(),
            backup: self.backup,
            backup_dir: Some(self.backup_dir.clone()),
            adopt: self.adopt,
        }
    }
}

/// Resolve dotfile packages across explicit CLI packages, profile selection,
/// ENSTOW_PACKAGES environment variable, config default profile, and config packages.
///
/// Precedence:
/// 1. Explicit CLI packages (if non-empty)
/// 2. Profile selection via `--profile` or `ENSTOW_PROFILE`
/// 3. `ENSTOW_PACKAGES` environment variable
/// 4. Config default (`default_profile`, then `config.packages`)
/// 5. Empty vec (stows all packages in source root)
pub fn resolve_packages(
    cli_packages: &[String],
    cli_profile: Option<&str>,
    config: Option<&ConfigFile>,
) -> Result<Vec<String>> {
    // 1. Explicit CLI packages (if non-empty)
    if !cli_packages.is_empty() {
        return Ok(cli_packages.to_vec());
    }

    // 2. Profile selection via --profile or ENSTOW_PROFILE
    let profile_name = cli_profile
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| {
            std::env::var("ENSTOW_PROFILE")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        });

    if let Some(name) = profile_name {
        if let Some(profile) = config
            .and_then(|c| c.profiles.as_ref())
            .and_then(|p| p.get(&name))
        {
            return Ok(profile.packages.clone());
        }

        let available = config
            .and_then(|c| c.profiles.as_ref())
            .map(|p| p.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        if available.is_empty() {
            anyhow::bail!("Unknown profile '{}'", name);
        } else {
            anyhow::bail!(
                "Unknown profile '{}'. Available profiles: {}",
                name,
                available.join(", ")
            );
        }
    }

    // 3. ENSTOW_PACKAGES environment variable
    if let Ok(pkg_env) = std::env::var("ENSTOW_PACKAGES") {
        if !pkg_env.trim().is_empty() {
            return Ok(pkg_env
                .split([',', ' '])
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect());
        }
    }

    // 4. Config default
    if let Some(def_profile) = config
        .and_then(|c| c.default_profile.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(profile) = config
            .and_then(|c| c.profiles.as_ref())
            .and_then(|p| p.get(def_profile))
        {
            return Ok(profile.packages.clone());
        }

        let available = config
            .and_then(|c| c.profiles.as_ref())
            .map(|p| p.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        if available.is_empty() {
            anyhow::bail!("Unknown default profile '{}'", def_profile);
        } else {
            anyhow::bail!(
                "Unknown default profile '{}'. Available profiles: {}",
                def_profile,
                available.join(", ")
            );
        }
    }

    if let Some(pkgs) = config.and_then(|c| c.packages.clone()) {
        return Ok(pkgs);
    }

    // 5. Default: empty vec (all packages in source root)
    Ok(Vec::new())
}

/// Resolve the active profile name, if any, across CLI flag, ENSTOW_PROFILE, and config default_profile.
pub fn resolve_profile(cli_profile: Option<&str>, config: Option<&ConfigFile>) -> Option<String> {
    cli_profile
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .or_else(|| {
            std::env::var("ENSTOW_PROFILE")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            config
                .and_then(|c| c.default_profile.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
        })
}

/// Resolve source directory precedence: CLI > ENSTOW_SOURCE > Config > Default (".")
pub fn resolve_source(cli_source: Option<&Path>, config: Option<&ConfigFile>) -> PathBuf {
    if let Some(s) = cli_source {
        s.to_path_buf()
    } else if let Ok(s_env) = std::env::var("ENSTOW_SOURCE") {
        if !s_env.trim().is_empty() {
            PathBuf::from(s_env)
        } else {
            config
                .and_then(|c| c.source.clone())
                .unwrap_or_else(|| PathBuf::from("."))
        }
    } else if let Some(s) = config.and_then(|c| c.source.clone()) {
        s
    } else {
        PathBuf::from(".")
    }
}

/// Resolve target directory precedence: CLI > ENSTOW_TARGET > Config > Default (HOME / ".")
pub fn resolve_target(cli_target: Option<&Path>, config: Option<&ConfigFile>) -> PathBuf {
    if let Some(t) = cli_target {
        t.to_path_buf()
    } else if let Ok(t_env) = std::env::var("ENSTOW_TARGET") {
        if !t_env.trim().is_empty() {
            PathBuf::from(t_env)
        } else {
            config
                .and_then(|c| c.target.clone())
                .unwrap_or_else(default_target_dir)
        }
    } else if let Some(t) = config.and_then(|c| c.target.clone()) {
        t
    } else {
        default_target_dir()
    }
}

/// Resolve dry-run precedence: CLI (-n / --dry-run) > ENSTOW_DRY_RUN > Config > Default (false)
pub fn resolve_dry_run(cli_dry_run: bool, config: Option<&ConfigFile>) -> bool {
    if cli_dry_run {
        true
    } else if let Some(env_dry_run) = parse_bool_env("ENSTOW_DRY_RUN") {
        env_dry_run
    } else {
        config.and_then(|c| c.dry_run).unwrap_or_default()
    }
}

/// Resolve common arguments across CLI args, environment variables, config file, and defaults.
pub fn resolve_common_args(
    cli_args: &CommonArgs,
    config: Option<&ConfigFile>,
) -> Result<ResolvedCommonArgs> {
    // 1. Source precedence: CLI > ENSTOW_SOURCE > Config > Default (".")
    let source = resolve_source(cli_args.source.as_deref(), config);

    // 2. Target precedence: CLI > ENSTOW_TARGET > Config > Default (HOME / ".")
    let target = resolve_target(cli_args.target.as_deref(), config);

    // 3. Age key file precedence: CLI > ENSTOW_AGE_KEY_FILE > SOPS_AGE_KEY_FILE > Config
    let age_key_file = resolve_age_key_file(cli_args.age_key_file.as_deref(), config);

    // 4. Packages and profile precedence
    let packages = resolve_packages(&cli_args.packages, cli_args.profile.as_deref(), config)?;
    let profile = resolve_profile(cli_args.profile.as_deref(), config);

    // 5. Additional ignore patterns: from CLI, ENSTOW_IGNORE, and Config
    let ignore = resolve_ignore_patterns(&cli_args.ignore, config);

    // 6. Dry run precedence: CLI (-n / --dry-run) > ENSTOW_DRY_RUN > Config > Default (false)
    let dry_run = resolve_dry_run(cli_args.dry_run, config);

    // 7. Force precedence: CLI (-f / --force) > ENSTOW_FORCE > Config > Default (false)
    let force = if cli_args.force {
        true
    } else if let Some(env_force) = parse_bool_env("ENSTOW_FORCE") {
        env_force
    } else {
        config.and_then(|c| c.force).unwrap_or_default()
    };

    // 8. Prune precedence: CLI (--prune) > ENSTOW_PRUNE > Config > Default (false)
    let prune = if cli_args.prune {
        true
    } else if let Some(env_prune) = parse_bool_env("ENSTOW_PRUNE") {
        env_prune
    } else {
        config.and_then(|c| c.prune).unwrap_or_default()
    };

    // 9. Backup precedence: CLI (-b / --backup) > ENSTOW_BACKUP > Config > Default (false)
    let backup = if cli_args.backup {
        true
    } else if let Some(env_backup) = parse_bool_env("ENSTOW_BACKUP") {
        env_backup
    } else {
        config.and_then(|c| c.backup).unwrap_or_default()
    };

    // 10. Backup directory precedence: CLI (--backup-dir) > ENSTOW_BACKUP_DIR > Config > Default ($target/.enstow-backup)
    let backup_dir = if let Some(bd) = &cli_args.backup_dir {
        bd.clone()
    } else if let Ok(bd_env) = std::env::var("ENSTOW_BACKUP_DIR") {
        if !bd_env.trim().is_empty() {
            PathBuf::from(bd_env)
        } else {
            config
                .and_then(|c| c.backup_dir.clone())
                .unwrap_or_else(|| target.join(".enstow-backup"))
        }
    } else if let Some(bd) = config.and_then(|c| c.backup_dir.clone()) {
        bd
    } else {
        target.join(".enstow-backup")
    };

    // 11. Target permissions: from Config permissions and package_permissions
    let permissions = resolve_permissions(config)?;

    // 12. Adopt precedence: CLI (--adopt) > ENSTOW_ADOPT > Config > Default (false)
    let adopt = if cli_args.adopt {
        true
    } else if let Some(env_adopt) = parse_bool_env("ENSTOW_ADOPT") {
        env_adopt
    } else {
        config.and_then(|c| c.adopt).unwrap_or_default()
    };

    Ok(ResolvedCommonArgs {
        source,
        target,
        dry_run,
        force,
        prune,
        age_key_file,
        profile,
        packages,
        ignore,
        backup,
        backup_dir,
        permissions,
        adopt,
    })
}

/// Resolve permission rules from configuration file.
pub fn resolve_permissions(config: Option<&ConfigFile>) -> Result<PermissionsConfig> {
    let mut result = PermissionsConfig::new();

    if let Some(cfg) = config {
        if let Some(perms) = &cfg.permissions {
            for (pattern, mode_repr) in perms {
                let mode = mode_repr.to_mode()?;
                result.add_rule(pattern.clone(), mode, None);
            }
        }

        if let Some(packages) = &cfg.package {
            for (pkg_name, pkg_cfg) in packages {
                for (pattern, mode_repr) in &pkg_cfg.permissions {
                    let mode = mode_repr.to_mode()?;
                    result.add_rule(pattern.clone(), mode, Some(pkg_name.clone()));
                }
            }
        }

        if let Some(package_perms) = &cfg.package_permissions {
            for (pkg_name, perms) in package_perms {
                for (pattern, mode_repr) in perms {
                    let mode = mode_repr.to_mode()?;
                    result.add_rule(pattern.clone(), mode, Some(pkg_name.clone()));
                }
            }
        }
    }

    Ok(result)
}

/// Parse a boolean value from an environment variable ("1", "true", "0", "false").
pub fn parse_bool_env(var: &str) -> Option<bool> {
    let val = std::env::var(var).ok()?;
    let trimmed = val.trim();
    if trimmed.eq_ignore_ascii_case("1") || trimmed.eq_ignore_ascii_case("true") {
        Some(true)
    } else if trimmed.eq_ignore_ascii_case("0") || trimmed.eq_ignore_ascii_case("false") {
        Some(false)
    } else {
        None
    }
}

/// Resolve JSON output precedence: CLI (--json) > ENSTOW_JSON > Config (json / output == "json") > Default (false)
pub fn resolve_json(cli_json: bool, config: Option<&ConfigFile>) -> bool {
    if cli_json {
        true
    } else if let Some(env_json) = parse_bool_env("ENSTOW_JSON") {
        env_json
    } else if let Some(cfg) = config {
        if let Some(j) = cfg.json {
            j
        } else if let Some(out) = &cfg.output {
            out.trim().eq_ignore_ascii_case("json")
        } else {
            false
        }
    } else {
        false
    }
}

/// Resolve mask_secrets precedence: CLI (--mask-secrets / --no-secrets) > ENSTOW_MASK_SECRETS > Config (mask_secrets) > Default (false)
pub fn resolve_mask_secrets(cli_mask_secrets: bool, config: Option<&ConfigFile>) -> bool {
    if cli_mask_secrets {
        true
    } else if let Some(env_mask) = parse_bool_env("ENSTOW_MASK_SECRETS") {
        env_mask
    } else if let Some(cfg) = config {
        cfg.mask_secrets.unwrap_or(false)
    } else {
        false
    }
}

/// Resolve editor precedence: CLI (--editor) > ENSTOW_EDITOR > VISUAL > EDITOR > Config (editor) > Default (None)
pub fn resolve_editor(cli_editor: Option<&str>, config: Option<&ConfigFile>) -> Option<String> {
    if let Some(ed) = cli_editor {
        if !ed.trim().is_empty() {
            return Some(ed.to_string());
        }
    }

    if let Ok(enstow_editor) = std::env::var("ENSTOW_EDITOR") {
        if !enstow_editor.trim().is_empty() {
            return Some(enstow_editor);
        }
    }

    if let Ok(visual) = std::env::var("VISUAL") {
        if !visual.trim().is_empty() {
            return Some(visual);
        }
    }

    if let Ok(editor) = std::env::var("EDITOR") {
        if !editor.trim().is_empty() {
            return Some(editor);
        }
    }

    if let Some(cfg_editor) = config.and_then(|c| c.editor.clone()) {
        if !cfg_editor.trim().is_empty() {
            return Some(cfg_editor);
        }
    }

    None
}

/// Resolve age recipient public keys precedence:
/// CLI (--recipient) > ENSTOW_RECIPIENTS > SOPS_AGE_RECIPIENTS > Config (recipients) > empty
pub fn resolve_recipients(cli_recipients: &[String], config: Option<&ConfigFile>) -> Vec<String> {
    if !cli_recipients.is_empty() {
        return cli_recipients.to_vec();
    }

    let parse_keys = |val: &str| -> Vec<String> {
        val.split([',', '\n'])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };

    if let Ok(recs_env) = std::env::var("ENSTOW_RECIPIENTS") {
        let keys = parse_keys(&recs_env);
        if !keys.is_empty() {
            return keys;
        }
    }

    if let Ok(recipients_env) = std::env::var("SOPS_AGE_RECIPIENTS") {
        let keys = parse_keys(&recipients_env);
        if !keys.is_empty() {
            return keys;
        }
    }

    if let Some(recipients_cfg) = config.and_then(|c| c.recipients.as_ref()) {
        let keys = recipients_cfg.to_recipients();
        if !keys.is_empty() {
            return keys;
        }
    }

    Vec::new()
}

/// Resolve age identity key file precedence:
/// CLI (--age-key-file) > ENSTOW_AGE_KEY_FILE > SOPS_AGE_KEY_FILE > Config (age_key_file) > None
pub fn resolve_age_key_file(
    cli_key_file: Option<&Path>,
    config: Option<&ConfigFile>,
) -> Option<PathBuf> {
    if let Some(k) = cli_key_file {
        return Some(k.to_path_buf());
    }

    if let Ok(k_env) = std::env::var("ENSTOW_AGE_KEY_FILE") {
        if !k_env.trim().is_empty() {
            return Some(PathBuf::from(k_env));
        }
    }

    if let Ok(k_env) = std::env::var("SOPS_AGE_KEY_FILE") {
        if !k_env.trim().is_empty() {
            return Some(PathBuf::from(k_env));
        }
    }

    config.and_then(|c| c.age_key_file.clone())
}

/// Resolve ignore patterns additively across CLI args, ENSTOW_IGNORE environment variable,
/// and configuration file, removing duplicates while preserving precedence order.
pub fn resolve_ignore_patterns(cli_ignore: &[String], config: Option<&ConfigFile>) -> Vec<String> {
    let mut result = Vec::new();

    let mut add_patterns = |patterns: &[String]| {
        for p in patterns {
            let trimmed = p.trim();
            if !trimmed.is_empty() && !result.iter().any(|existing: &String| existing == trimmed) {
                result.push(trimmed.to_string());
            }
        }
    };

    // 1. CLI arguments
    add_patterns(cli_ignore);

    // 2. ENSTOW_IGNORE environment variable (comma or colon separated)
    if let Ok(env_ignore) = std::env::var("ENSTOW_IGNORE") {
        let env_patterns: Vec<String> = env_ignore
            .split([',', ':'])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        add_patterns(&env_patterns);
    }

    // 3. Configuration file
    if let Some(cfg_ignore) = config.and_then(|c| c.ignore.as_ref()) {
        add_patterns(cfg_ignore);
    }

    result
}

/// Resolve log level across CLI flags, environment variables, config file, and defaults.
/// Precedence: CLI (--log-level, -v, -q) > ENSTOW_LOG_LEVEL > RUST_LOG > Config (log_level) > Default ("info")
pub fn resolve_log_level(
    cli_log_level: Option<&str>,
    verbose: u8,
    quiet: u8,
    config: Option<&ConfigFile>,
) -> String {
    // 1. CLI explicit flag: --log-level
    if let Some(level) = cli_log_level {
        let trimmed = level.trim();
        if !trimmed.is_empty() {
            return trimmed.to_lowercase();
        }
    }

    // CLI -v / --verbose flag (1 -> debug, >=2 -> trace)
    if verbose > 0 {
        return if verbose >= 2 {
            "trace".to_string()
        } else {
            "debug".to_string()
        };
    }

    // CLI -q / --quiet flag (1 -> warn, >=2 -> error)
    if quiet > 0 {
        return if quiet >= 2 {
            "error".to_string()
        } else {
            "warn".to_string()
        };
    }

    // 2. Environment variables: ENSTOW_LOG_LEVEL with fallback to RUST_LOG
    if let Ok(val) = std::env::var("ENSTOW_LOG_LEVEL") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_lowercase();
        }
    }

    if let Ok(val) = std::env::var("RUST_LOG") {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return trimmed.to_lowercase();
        }
    }

    // 3. Configuration file
    if let Some(cfg) = config {
        if let Some(val) = &cfg.log_level {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return trimmed.to_lowercase();
            }
        }
    }

    // 4. Default: "info"
    "info".to_string()
}

/// Initialize `tracing_subscriber` with dynamic level filter based on resolved settings.
pub fn init_tracing(level_str: &str) -> Result<()> {
    let filter = tracing_subscriber::filter::EnvFilter::try_new(level_str)
        .with_context(|| format!("Invalid log level filter '{level_str}'"))?;
    let subscriber = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();
    Ok(())
}
