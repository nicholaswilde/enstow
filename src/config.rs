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
    #[serde(default)]
    pub hooks: Option<HooksConfig>,
}

/// Lifecycle hooks configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct HooksConfig {
    #[serde(
        default,
        deserialize_with = "deserialize_hook_commands",
        alias = "pre_stow",
        alias = "pre_sync"
    )]
    pub pre_apply: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_hook_commands",
        alias = "post_stow",
        alias = "post_sync"
    )]
    pub post_apply: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_hook_commands",
        alias = "pre_delete",
        alias = "pre_remove"
    )]
    pub pre_unstow: Vec<String>,
    #[serde(
        default,
        deserialize_with = "deserialize_hook_commands",
        alias = "post_delete",
        alias = "post_remove"
    )]
    pub post_unstow: Vec<String>,
}

pub fn deserialize_hook_commands<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct StringOrVec;

    impl<'de> serde::de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string command or a list of string commands")
        }

        fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(vec![value.to_string()])
        }

        fn visit_seq<S>(self, mut visitor: S) -> std::result::Result<Self::Value, S::Error>
        where
            S: serde::de::SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(elem) = visitor.next_element::<String>()? {
                vec.push(elem);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_any(StringOrVec)
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
    pub hooks: Option<HooksConfig>,
    pub package: Option<BTreeMap<String, PackageConfig>>,
    pub package_permissions: Option<BTreeMap<String, BTreeMap<String, PermissionMode>>>,
    pub package_hooks: Option<BTreeMap<String, HooksConfig>>,
    pub no_hooks: Option<bool>,
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

/// Compiled lifecycle hooks across global and package scopes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvedHooks {
    pub global: HooksConfig,
    pub packages: BTreeMap<String, HooksConfig>,
}

pub fn resolve_hooks(config: Option<&ConfigFile>) -> ResolvedHooks {
    let mut resolved = ResolvedHooks::default();
    if let Some(cfg) = config {
        if let Some(hooks) = &cfg.hooks {
            resolved.global = hooks.clone();
        }
        if let Some(pkg_map) = &cfg.package {
            for (pkg_name, pkg_cfg) in pkg_map {
                if let Some(hooks) = &pkg_cfg.hooks {
                    resolved.packages.insert(pkg_name.clone(), hooks.clone());
                }
            }
        }
        if let Some(pkg_hooks) = &cfg.package_hooks {
            for (pkg_name, hooks) in pkg_hooks {
                resolved.packages.insert(pkg_name.clone(), hooks.clone());
            }
        }
    }
    resolved
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
    pub no_hooks: bool,
    pub hooks: ResolvedHooks,
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
            no_hooks: self.no_hooks,
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

    // 13. No hooks precedence: CLI (--no-hooks) > ENSTOW_NO_HOOKS > Config > Default (false)
    let no_hooks = if cli_args.no_hooks {
        true
    } else if let Some(env_no_hooks) = parse_bool_env("ENSTOW_NO_HOOKS") {
        env_no_hooks
    } else {
        config.and_then(|c| c.no_hooks).unwrap_or_default()
    };

    // 14. Lifecycle hooks resolution
    let hooks = resolve_hooks(config);

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
        no_hooks,
        hooks,
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_format_from_path() {
        assert_eq!(
            ConfigFormat::from_path(Path::new("config.toml")),
            Some(ConfigFormat::Toml)
        );
        assert_eq!(
            ConfigFormat::from_path(Path::new("config.yaml")),
            Some(ConfigFormat::Yaml)
        );
        assert_eq!(
            ConfigFormat::from_path(Path::new("config.yml")),
            Some(ConfigFormat::Yaml)
        );
        assert_eq!(
            ConfigFormat::from_path(Path::new("config.json")),
            Some(ConfigFormat::Json)
        );
        assert_eq!(ConfigFormat::from_path(Path::new("config.txt")), None);
        assert_eq!(ConfigFormat::from_path(Path::new("config")), None);
    }

    #[test]
    fn test_recipients_config() {
        let single = RecipientsConfig::Single("key1, key2\nkey3".to_string());
        assert_eq!(single.to_recipients(), vec!["key1", "key2", "key3"]);

        let list =
            RecipientsConfig::List(vec!["key1, key2".to_string(), " key3 \n key4 ".to_string()]);
        assert_eq!(list.to_recipients(), vec!["key1", "key2", "key3", "key4"]);
    }

    #[test]
    fn test_permission_mode_and_parse() {
        assert_eq!(parse_mode_str("600").unwrap(), 0o600);
        assert_eq!(parse_mode_str("0644").unwrap(), 0o644);
        assert_eq!(parse_mode_str("0o755").unwrap(), 0o755);
        assert_eq!(parse_mode_str("0").unwrap(), 0);
        assert!(parse_mode_str("888").is_err());
        assert!(parse_mode_str("xyz").is_err());

        assert_eq!(parse_mode_int(600).unwrap(), 0o600);
        assert_eq!(parse_mode_int(0o644).unwrap(), 0o644);
        assert_eq!(parse_mode_int(0o7777).unwrap(), 0o7777);
        assert!(parse_mode_int(0o10000).is_err());

        let pm_str = PermissionMode::Str("600".to_string());
        assert_eq!(pm_str.to_mode().unwrap(), 0o600);

        let pm_int = PermissionMode::Int(644);
        assert_eq!(pm_int.to_mode().unwrap(), 0o644);
    }

    #[test]
    fn test_config_parse_all_formats() {
        let toml_str = r#"
            source = "dotfiles"
            target = "home"
            packages = ["bash", "git"]
        "#;
        let cfg_toml = ConfigFile::parse(toml_str, ConfigFormat::Toml).unwrap();
        assert_eq!(cfg_toml.source, Some(PathBuf::from("dotfiles")));
        assert_eq!(cfg_toml.target, Some(PathBuf::from("home")));
        assert_eq!(
            cfg_toml.packages,
            Some(vec!["bash".to_string(), "git".to_string()])
        );

        let yaml_str = r#"
            source: dotfiles
            target: home
            packages:
              - bash
              - git
        "#;
        let cfg_yaml = ConfigFile::parse(yaml_str, ConfigFormat::Yaml).unwrap();
        assert_eq!(cfg_yaml.source, Some(PathBuf::from("dotfiles")));

        let json_str = r#"{
            "source": "dotfiles",
            "target": "home"
        }"#;
        let cfg_json = ConfigFile::parse(json_str, ConfigFormat::Json).unwrap();
        assert_eq!(cfg_json.source, Some(PathBuf::from("dotfiles")));
    }

    #[test]
    fn test_load_config_and_load_from_path() {
        let dir = tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        fs::write(&cfg_path, "source = \"my_source\"\n").unwrap();

        // Valid explicit load
        let (p, loaded) = load_config(Some(&cfg_path)).unwrap().unwrap();
        assert_eq!(p, cfg_path);
        assert_eq!(loaded.source, Some(PathBuf::from("my_source")));

        // Missing file
        let missing = dir.path().join("missing.toml");
        assert!(load_config(Some(&missing)).is_err());

        // Directory instead of file
        assert!(load_config(Some(dir.path())).is_err());

        // Unsupported extension
        let txt_path = dir.path().join("config.txt");
        fs::write(&txt_path, "source = \"txt\"\n").unwrap();
        assert!(ConfigFile::load_from_path(&txt_path).is_err());
    }

    #[test]
    fn test_permissions_config_resolve_mode() {
        let mut pc = PermissionsConfig::new();
        pc.add_rule("*.sh".to_string(), 0o755, Some("shell_pkg".to_string()));
        pc.add_rule("id_ed25519*".to_string(), 0o600, None);

        let target_root = Path::new("/home/user");
        let shell_target = Path::new("/home/user/.local/bin/script.sh");
        let shell_source = Path::new("/dotfiles/shell_pkg/.local/bin/script.sh");

        // Matches pattern and package
        assert_eq!(
            pc.resolve_mode(shell_target, Some(shell_source), Some(target_root)),
            0o755
        );

        // Does not match package
        let other_source = Path::new("/dotfiles/other_pkg/.local/bin/script.sh");
        assert_eq!(
            pc.resolve_mode(shell_target, Some(other_source), Some(target_root)),
            0o600
        );

        // Matches global rule without package restriction
        let key_target = Path::new("/home/user/.ssh/id_ed25519");
        assert_eq!(pc.resolve_mode(key_target, None, Some(target_root)), 0o600);
    }

    #[test]
    fn test_resolve_hooks() {
        let mut cfg = ConfigFile::default();
        let mut global_hooks = HooksConfig::default();
        global_hooks.pre_apply.push("echo pre".to_string());
        cfg.hooks = Some(global_hooks);

        let mut pkg_map = BTreeMap::new();
        let mut pkg_cfg = PackageConfig::default();
        let mut pkg_hooks = HooksConfig::default();
        pkg_hooks.post_apply.push("echo post".to_string());
        pkg_cfg.hooks = Some(pkg_hooks);
        pkg_map.insert("pkg1".to_string(), pkg_cfg);
        cfg.package = Some(pkg_map);

        let resolved = resolve_hooks(Some(&cfg));
        assert_eq!(resolved.global.pre_apply, vec!["echo pre"]);
        assert_eq!(
            resolved.packages.get("pkg1").unwrap().post_apply,
            vec!["echo post"]
        );
    }

    #[test]
    fn test_resolve_packages() {
        let mut cfg = ConfigFile::default();
        let mut profiles = BTreeMap::new();
        profiles.insert(
            "work".to_string(),
            ProfileConfig {
                packages: vec!["work_pkg".to_string()],
            },
        );
        cfg.profiles = Some(profiles);
        cfg.packages = Some(vec!["default_pkg".to_string()]);

        // 1. Explicit CLI packages
        let cli_pkgs = vec!["custom_pkg".to_string()];
        assert_eq!(
            resolve_packages(&cli_pkgs, None, Some(&cfg)).unwrap(),
            vec!["custom_pkg"]
        );

        // 2. Profile selection
        assert_eq!(
            resolve_packages(&[], Some("work"), Some(&cfg)).unwrap(),
            vec!["work_pkg"]
        );
        assert!(resolve_packages(&[], Some("nonexistent"), Some(&cfg)).is_err());

        // 3. Config packages
        assert_eq!(
            resolve_packages(&[], None, Some(&cfg)).unwrap(),
            vec!["default_pkg"]
        );

        // 4. Default profile
        cfg.default_profile = Some("work".to_string());
        assert_eq!(
            resolve_packages(&[], None, Some(&cfg)).unwrap(),
            vec!["work_pkg"]
        );

        // 5. None
        assert_eq!(
            resolve_packages(&[], None, None).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn test_resolve_profile() {
        let cfg = ConfigFile {
            default_profile: Some("work".to_string()),
            ..Default::default()
        };

        assert_eq!(
            resolve_profile(Some("cli_profile"), Some(&cfg)),
            Some("cli_profile".to_string())
        );
        assert_eq!(resolve_profile(None, Some(&cfg)), Some("work".to_string()));
        assert_eq!(resolve_profile(None, None), None);
    }

    #[test]
    fn test_resolve_source_and_target() {
        let cfg = ConfigFile {
            source: Some(PathBuf::from("/cfg/source")),
            target: Some(PathBuf::from("/cfg/target")),
            ..Default::default()
        };

        assert_eq!(
            resolve_source(Some(Path::new("/cli/source")), Some(&cfg)),
            PathBuf::from("/cli/source")
        );
        assert_eq!(
            resolve_source(None, Some(&cfg)),
            PathBuf::from("/cfg/source")
        );
        assert_eq!(resolve_source(None, None), PathBuf::from("."));

        assert_eq!(
            resolve_target(Some(Path::new("/cli/target")), Some(&cfg)),
            PathBuf::from("/cli/target")
        );
        assert_eq!(
            resolve_target(None, Some(&cfg)),
            PathBuf::from("/cfg/target")
        );
    }

    #[test]
    fn test_resolve_dry_run() {
        let cfg = ConfigFile {
            dry_run: Some(true),
            ..Default::default()
        };

        assert!(resolve_dry_run(true, None));
        assert!(resolve_dry_run(false, Some(&cfg)));
        assert!(!resolve_dry_run(false, None));
    }

    #[test]
    fn test_parse_bool_env() {
        assert_eq!(parse_bool_env("NON_EXISTENT_VAR_12345"), None);
    }

    #[test]
    fn test_resolve_json_and_mask_secrets() {
        let cfg = ConfigFile {
            json: Some(true),
            mask_secrets: Some(true),
            ..Default::default()
        };

        assert!(resolve_json(true, None));
        assert!(resolve_json(false, Some(&cfg)));
        assert!(!resolve_json(false, None));

        assert!(resolve_mask_secrets(true, None));
        assert!(resolve_mask_secrets(false, Some(&cfg)));
        assert!(!resolve_mask_secrets(false, None));
    }

    #[test]
    fn test_resolve_editor_and_recipients() {
        let cfg = ConfigFile {
            editor: Some("nano".to_string()),
            recipients: Some(RecipientsConfig::Single("cfg_key".to_string())),
            ..Default::default()
        };

        // CLI overrides everything
        assert_eq!(
            resolve_editor(Some("vim"), Some(&cfg)),
            Some("vim".to_string())
        );

        let cli_recipients = vec!["cli_key".to_string()];
        assert_eq!(
            resolve_recipients(&cli_recipients, Some(&cfg)),
            vec!["cli_key".to_string()]
        );
    }

    #[test]
    fn test_resolve_age_key_file_and_ignore_patterns() {
        let cfg = ConfigFile {
            age_key_file: Some(PathBuf::from("/cfg/key")),
            ignore: Some(vec!["*.swp".to_string()]),
            ..Default::default()
        };

        // CLI overrides everything
        assert_eq!(
            resolve_age_key_file(Some(Path::new("/cli/key")), Some(&cfg)),
            Some(PathBuf::from("/cli/key"))
        );

        let cli_ignore = vec!["*.bak".to_string()];
        assert_eq!(
            resolve_ignore_patterns(&cli_ignore, Some(&cfg)),
            vec!["*.bak".to_string(), "*.swp".to_string()]
        );
        assert_eq!(
            resolve_ignore_patterns(&[], Some(&cfg)),
            vec!["*.swp".to_string()]
        );
    }

    #[test]
    fn test_resolve_log_level_and_init_tracing() {
        let cfg = ConfigFile {
            log_level: Some("warn".to_string()),
            ..Default::default()
        };

        assert_eq!(resolve_log_level(Some("debug"), 0, 0, None), "debug");
        assert_eq!(resolve_log_level(None, 1, 0, None), "debug");
        assert_eq!(resolve_log_level(None, 2, 0, None), "trace");
        assert_eq!(resolve_log_level(None, 0, 1, None), "warn");
        assert_eq!(resolve_log_level(None, 0, 2, None), "error");
        assert_eq!(resolve_log_level(None, 0, 0, Some(&cfg)), "warn");
        assert_eq!(resolve_log_level(None, 0, 0, None), "info");

        assert!(init_tracing("info").is_ok());
        assert!(init_tracing("[invalid]=foo").is_err());
    }

    #[test]
    fn test_resolve_common_args() {
        let common = CommonArgs {
            source: Some(PathBuf::from("/src")),
            target: Some(PathBuf::from("/tgt")),
            dry_run: true,
            force: true,
            packages: vec!["pkg1".to_string()],
            ..Default::default()
        };

        let resolved = resolve_common_args(&common, None).unwrap();
        assert_eq!(resolved.source, PathBuf::from("/src"));
        assert_eq!(resolved.target, PathBuf::from("/tgt"));
        assert!(resolved.dry_run);
        assert!(resolved.force);
        assert_eq!(resolved.packages, vec!["pkg1"]);

        let back_to_common = resolved.to_common_args();
        assert_eq!(back_to_common.source, Some(PathBuf::from("/src")));
        assert!(back_to_common.dry_run);
    }
}
