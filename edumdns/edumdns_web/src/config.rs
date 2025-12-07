use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct WebConfig {
    #[serde(default = "default_web_hostname")]
    pub hostname: String,
    #[serde(default = "default_web_hostname")]
    pub site_url: String,
    #[serde(default = "default_static_files_dir")]
    pub static_files_dir: String,
    pub session_cookie: String,
    #[serde(default)]
    pub session: SessionExpirationConfig,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub oidc: Option<OidcConfig>,
    #[serde(default)]
    pub external_auth_database: Option<ExternalAuthDatabase>,
}

fn default_web_hostname() -> String {
    "localhost:8000".to_string()
}
fn default_static_files_dir() -> String {
    "edumdns_web".to_string()
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct OidcConfig {
    pub client_id: String,
    pub client_secret: String,
    pub issuer: String,
    pub callback_url: String,
    pub new_users_admin: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct ExternalAuthDatabase {
    pub connection_string: String,
    pub auth_query: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct SessionExpirationConfig {
    pub session_expiration: u64,
    pub last_visit_deadline: u64,
    pub use_secure_cookie: bool,
}

impl Default for SessionExpirationConfig {
    fn default() -> Self {
        Self {
            session_expiration: 2592000,
            last_visit_deadline: 604800,
            use_secure_cookie: true,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct Limits {
    pub payload_limit: usize,
    pub form_limit: usize,
    pub probe_ping_interval: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            payload_limit: 17179869184,
            form_limit: 16777216,
            probe_ping_interval: 1,
        }
    }
}