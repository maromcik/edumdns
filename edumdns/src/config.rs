use crate::error::AppError;
use config::Config;
use edumdns_db::config::DbConfig;
use edumdns_server::config::ServerConfig;
use edumdns_web::config::WebConfig;
use serde::{Deserialize, Serialize};

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
    pub fn parse_config(settings_path: &str) -> Result<AppConfig, AppError> {
        let settings = Config::builder()
            .add_source(config::File::with_name(settings_path))
            .add_source(config::Environment::with_prefix("APP"))
            .build()?;

        let config = settings.try_deserialize::<AppConfig>()?;

        Ok(config)
    }
}
