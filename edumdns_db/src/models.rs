use chrono::{DateTime, Utc};
use crate::repositories::common::Id;
use diesel::prelude::*;
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, PrimitiveDateTime, UtcDateTime};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::group)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Group {
    pub id: Id,
    pub name: String,
}

#[derive(Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::location)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Location {
    pub id: Id,
    pub name: String,
}

#[derive(Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::probe)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct Probe {
    pub id: Uuid,
    pub owner_id: Option<Id>,
    pub location_id: Option<Id>,
    pub adopted: bool,
    pub mac: [u8; 6],
    pub ip: ipnetwork::IpNetwork,
    pub port: i32,
    pub vlan: Option<i32>,
}

#[derive(Serialize, Deserialize, Queryable, Selectable)]
#[diesel(table_name = crate::schema::user)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct User {
    pub id: Id,
    pub email: String,
    pub name: String,
    pub surname: String,
    pub password_hash: String,
    pub password_salt: String,
    pub admin: bool,
    pub created_at: OffsetDateTime,
    pub edited_at: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
}

