use crate::repositories::common::Id;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::group)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Group {
    pub id: Id,
    pub name: String,
}