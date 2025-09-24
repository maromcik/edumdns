use crate::repositories::common::{Id, Pagination};
use crate::repositories::utilities::empty_string_is_none;
use diesel::{AsChangeset, Identifiable, Insertable};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct SelectManyUsers {
    pub id: Option<Id>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub surname: Option<String>,
    pub admin: Option<bool>,
    pub disabled: Option<bool>,
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

#[derive(Serialize, Deserialize, Debug, Clone, Default, AsChangeset, Identifiable)]
#[diesel(table_name = crate::schema::user)]
pub struct UserUpdate {
    pub id: Id,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub email: Option<String>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub surname: Option<String>,
    #[serde(default)]
    pub admin: Option<bool>,
    #[serde(default)]
    pub disabled: Option<bool>,
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
        disabled: Option<bool>,
    ) -> Self {
        let change_to_owned = |value: &str| Some(value.to_owned());
        Self {
            id: *id,
            email: email.and_then(change_to_owned),
            name: name.and_then(change_to_owned),
            surname: surname.and_then(change_to_owned),
            admin,
            disabled
        }
    }
}

#[derive(Serialize, Deserialize, AsChangeset, Insertable, Debug)]
#[diesel(table_name = crate::schema::user)]
pub struct UserCreate {
    pub id: Id,
    pub email: String,
    pub name: String,
    pub surname: String,
    pub password_hash: Option<String>,
    pub password_salt: Option<String>,
    pub admin: bool,
}

impl UserCreate {
    pub fn new_from_oidc(
        id: Id,
        email: &str,
        name: &str,
        surname: &str,
        password_hash: Option<&str>,
        password_salt: Option<&str>,
        admin: bool,
    ) -> Self {
        Self {
            id,
            email: email.to_owned(),
            name: name.to_owned(),
            surname: surname.to_owned(),
            password_hash: password_hash.map(|v| v.to_owned()),
            password_salt: password_salt.map(|v| v.to_owned()),
            admin,
        }
    }

    pub fn new_from_admin(email: &str, name: &str, surname: &str, admin: bool) -> Self {
        Self {
            id: 0,
            email: email.to_owned(),
            name: name.to_owned(),
            surname: surname.to_owned(),
            password_hash: None,
            password_salt: None,
            admin,
        }
    }
}
