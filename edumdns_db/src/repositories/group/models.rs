use crate::repositories::common::{Id, Pagination};
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

#[derive(Serialize, Deserialize)]
pub struct CreateGroup {
    pub user_id: Id,
    pub name: String,
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
