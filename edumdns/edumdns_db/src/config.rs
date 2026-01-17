use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
pub struct DbConfig {
    pub connection_string: String,
    #[serde(default = "default_database_pool_size")]
    pub pool_size: usize,
}

fn default_database_pool_size() -> usize {
    20
}
