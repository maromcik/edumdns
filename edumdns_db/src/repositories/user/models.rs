use diesel::{AsChangeset, Identifiable};
use crate::repositories::common::{Id, Pagination};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Serialize, Deserialize)]
pub struct SelectManyUsers {
    pub email: Option<String>,
    pub name: Option<String>,
    pub surname: Option<String>,
    pub admin: Option<bool>,
    pub deleted: Option<bool>,
    pub pagination: Option<Pagination>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserLogin {
    pub email: String,
    pub password: String,
}

impl UserLogin {
    #[must_use]
    #[inline]
    pub fn new(email: &str, password_hash: &str) -> Self {
        Self {
            email: email.to_owned(),
            password: password_hash.to_owned(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserUpdatePassword {
    pub id: Id,
    pub old_password: String,
    pub new_password: String,
}

impl UserUpdatePassword {
    pub fn new(id: &Id, old_password: &str, new_password: &str) -> Self {
        Self {
            id: *id,
            old_password: old_password.to_owned(),
            new_password: new_password.to_owned(),
        }
    }
}

#[derive(Debug, Clone, Default, AsChangeset, Identifiable)]
#[diesel(table_name = crate::schema::user)]
pub struct UserUpdate {
    pub id: Id,
    pub email: Option<String>,
    pub name: Option<String>,
    pub surname: Option<String>,
    pub admin: Option<bool>,
}

impl UserUpdate {
    #[must_use]
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: &Id,
        email: Option<&str>,
        name: Option<&str>,
        surname: Option<&str>,
        admin: Option<bool>,
    ) -> Self {
        let change_to_owned = |value: &str| Some(value.to_owned());
        Self {
            id: *id,
            email: email.and_then(change_to_owned),
            name: name.and_then(change_to_owned),
            surname: surname.and_then(change_to_owned),
            admin,
        }
    }
}