use crate::repositories::common::Pagination;
use crate::repositories::utilities::empty_string_is_none;
use diesel::{AsChangeset, Identifiable};
use edumdns_core::app_packet::Id;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SelectManyGroups {
    pub name: Option<String>,
    pub description: Option<String>,
    pub pagination: Option<Pagination>,
}

impl SelectManyGroups {
    pub fn new(
        name: Option<String>,
        description: Option<String>,
        pagination: Option<Pagination>,
    ) -> Self {
        Self {
            name,
            description,
            pagination,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateGroup {
    pub name: String,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub description: Option<String>,
}

impl CreateGroup {
    pub fn new<S: AsRef<str>>(name: &str, description: Option<S>) -> Self {
        Self {
            name: name.to_string(),
            description: description.map(|s| s.as_ref().to_string()),
        }
    }
}

#[derive(Serialize, Deserialize, AsChangeset, Identifiable, Debug)]
#[diesel(table_name = crate::schema::group)]
pub struct UpdateGroup {
    pub id: Id,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    #[diesel(treat_none_as_null = true)]
    pub description: Option<String>,
}
