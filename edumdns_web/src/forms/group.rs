use edumdns_db::repositories::common::Id;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashSet;
use edumdns_db::repositories::utilities::empty_string_is_none;

#[derive(Serialize, Deserialize)]
pub struct GroupQuery {
    pub page: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateGroupForm {
    pub name: String,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub description: Option<String>,
}

#[derive(Debug)]
pub struct AddGroupUsersForm {
    pub user_ids: Vec<Id>,
}
impl<'de> Deserialize<'de> for AddGroupUsersForm {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let pairs = Vec::<(String, String)>::deserialize(deserializer)?;
        let ids = pairs
            .into_iter()
            .filter_map(|(k, v)| if k == "user_ids[]" { Some(v) } else { None })
            .filter_map(|id| id.parse::<Id>().ok())
            .collect::<HashSet<Id>>();
        Ok(AddGroupUsersForm {
            user_ids: Vec::from_iter(ids),
        })
    }
}

#[derive(serde::Deserialize)]
pub struct SearchUsersQuery {
    pub q: String,
}
