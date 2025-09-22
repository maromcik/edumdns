use diesel::{AsChangeset, Identifiable};
use crate::repositories::common::{Id, Pagination};
use crate::repositories::utilities::empty_string_is_none;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SelectManyGroups {
    pub name: Option<String>,
    pub pagination: Option<Pagination>,
}

impl SelectManyGroups {
    pub fn new(name: Option<String>, pagination: Option<Pagination>) -> Self {
        Self { name, pagination }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CreateGroup {
    pub user_id: Id,
    pub name: String,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub description: Option<String>,
}

impl CreateGroup {
    pub fn new(user_id: Id, name: &String, description: Option<&String>) -> Self {
        Self {
            user_id,
            name: name.to_string(),
            description: description.map(|s| s.to_string()),
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