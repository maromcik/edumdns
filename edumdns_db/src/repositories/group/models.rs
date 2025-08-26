use crate::repositories::common::{Id, Pagination};
use diesel::{AsChangeset, Insertable};
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

#[derive(Serialize, Deserialize, AsChangeset, Insertable)]
#[diesel(table_name = crate::schema::group)]
pub struct CreateGroup {
    pub name: String,
}
