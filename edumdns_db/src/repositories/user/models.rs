use crate::repositories::common::Pagination;
use crate::repositories::utilities::{
    empty_string_is_none, generate_salt, hash_password, validate_password,
};

use crate::error::{BackendError, BackendErrorKind, DbError, DbErrorKind};
use crate::models::User;
use diesel::{AsChangeset, Identifiable, Insertable};
use edumdns_core::app_packet::Id;
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
    pub admin_id: Option<Id>,
    pub old_password: Option<String>,
    pub new_password: String,
}

impl UserUpdatePassword {
    pub fn new(id: &Id, old_password: &str, new_password: &str) -> Self {
        Self {
            id: *id,
            admin_id: None,
            old_password: Some(old_password.to_string()),
            new_password: new_password.to_owned(),
        }
    }

    pub fn new_from_admin(
        id: &Id,
        admin_id: &Id,
        new_password: &str,
        confirm_password: &str,
    ) -> Result<Self, DbError> {
        if new_password != confirm_password {
            return Err(DbError::new(
                DbErrorKind::BackendError(BackendError::new(
                    BackendErrorKind::UserPasswordVerificationFailed,
                    "Provided passwords do not match",
                )),
                "",
            ));
        }
        if !validate_password(new_password) {
            return Err(DbError::new(
                DbErrorKind::BackendError(BackendError::new(
                    BackendErrorKind::UserPasswordVerificationFailed,
                    "Provided password is not strong enough",
                )),
                "",
            ));
        }
        Ok(Self {
            id: *id,
            admin_id: Some(*admin_id),
            old_password: None,
            new_password: new_password.to_owned(),
        })
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
    pub admin: Option<bool>,
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
            disabled,
        }
    }
}

#[derive(Serialize, Deserialize, AsChangeset, Insertable, Debug)]
#[diesel(table_name = crate::schema::user)]
pub struct UserCreate {
    pub id: Option<Id>,
    pub email: String,
    pub name: String,
    pub surname: String,
    pub password_hash: Option<String>,
    pub password_salt: Option<String>,
    pub admin: bool,
}

impl UserCreate {
    pub fn new_from_oidc(id: Id, email: &str, name: &str, surname: &str, admin: bool) -> Self {
        Self {
            id: Some(id),
            email: email.to_owned(),
            name: name.to_owned(),
            surname: surname.to_owned(),
            password_hash: None,
            password_salt: None,
            admin,
        }
    }

    pub fn new_from_admin(
        email: &str,
        name: &str,
        surname: &str,
        admin: bool,
        password: &str,
        confirm_password: &str,
    ) -> Result<Self, DbError> {
        if password != confirm_password {
            return Err(DbError::new(
                DbErrorKind::BackendError(BackendError::new(
                    BackendErrorKind::UserPasswordVerificationFailed,
                    "Provided passwords do not match",
                )),
                "",
            ));
        }
        if !validate_password(password) {
            return Err(DbError::new(
                DbErrorKind::BackendError(BackendError::new(
                    BackendErrorKind::UserPasswordVerificationFailed,
                    "Provided password is not strong enough",
                )),
                "",
            ));
        }
        let password_salt = generate_salt();
        let password_hash = hash_password(password.to_owned(), &password_salt)?;
        Ok(Self {
            id: None,
            email: email.to_owned(),
            name: name.to_owned(),
            surname: surname.to_owned(),
            password_hash: Some(password_hash),
            password_salt: Some(password_salt.to_string()),
            admin,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDisplay {
    pub user: User,
    pub has_groups: bool,
}

impl UserDisplay {
    pub fn from(user: User, has_groups: bool) -> Self {
        Self { user, has_groups }
    }
}
