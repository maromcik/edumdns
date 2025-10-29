use edumdns_db::repositories::utilities::empty_string_is_none;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Serialize, Deserialize)]
pub struct GroupQuery {
    pub page: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub description: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateGroupForm {
    pub name: String,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub description: Option<String>,
}
