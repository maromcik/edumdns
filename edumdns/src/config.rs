//! Application configuration structure and parsing.
//!
//! This module defines the top-level `AppConfig` structure that combines configuration
//! from all system components (database, server, web). It provides functionality to
//! parse configuration from TOML files and environment variables.

use crate::error::AppError;
use config::Config;
use edumdns_db::config::DbConfig;
use edumdns_server::config::ServerConfig;
use edumdns_web::config::WebConfig;
use serde::{Deserialize, Serialize};

/// Top-level application configuration combining all component configurations.
///
/// This structure contains:
/// - Logging configuration (app and global log levels)
/// - Database configuration (`DbConfig`)
/// - Server component configuration (`ServerConfig`)
/// - Web component configuration (`WebConfig`)
///
/// Configuration is loaded from a TOML file and can be overridden by environment
/// variables with the `APP_` prefix.
#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq)]
pub struct AppConfig {
    #[serde(default = "default_log_level")]
    pub app_log_level: String,
    #[serde(default = "default_log_level")]
    pub all_log_level: String,
    pub database: DbConfig,
    #[serde(default)]
    pub server: ServerConfig,
    pub web: WebConfig,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl AppConfig {
    /// Parses configuration from a TOML file with environment variable overrides.
    ///
    /// This function loads configuration from:
    /// 1. A TOML file at the specified path
    /// 2. Environment variables with the `APP_` prefix (override TOML values)
    ///
    /// Environment variable names use dot notation: `APP_SERVER_HOSTNAMES` maps to
    /// `server.hostnames`, `APP_WEB_SESSION_SESSION_EXPIRATION` maps to
    /// `web.session.session_expiration`, etc.
    ///
    /// # Arguments
    ///
    /// * `settings_path` - Path to the TOML configuration file
    ///
    /// # Returns
    ///
    /// Returns `Ok(AppConfig)` if the configuration is successfully loaded and parsed,
    /// or an `AppError` if:
    /// - The configuration file cannot be read
    /// - The TOML syntax is invalid
    /// - Required configuration values are missing
    /// - Configuration values have invalid types or formats
    ///
    /// # Example
    ///
    /// ```no_run
    /// use edumdns::config::AppConfig;
    ///
    /// let config = AppConfig::parse_config("edumdns.toml")?;
    /// ```
    pub fn parse_config(settings_path: &str) -> Result<AppConfig, AppError> {
        let settings = Config::builder()
            .add_source(config::File::with_name(settings_path))
            .add_source(config::Environment::with_prefix("APP"))
            .build()?;

        let config = settings.try_deserialize::<AppConfig>()?;

        Ok(config)
    }
}
