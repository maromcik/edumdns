use actix_csrf::extractor::{Csrf, CsrfGuarded, CsrfToken};
use edumdns_core::app_packet::Id;
use edumdns_db::repositories::common::Pagination;
use edumdns_db::repositories::user::models::{SelectManyUsers, UserUpdate};
use edumdns_db::repositories::utilities::empty_string_is_none;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Serialize, Deserialize, Clone)]
pub struct UserQuery {
    pub page: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub id: Option<Id>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub surname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub admin: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub disabled: Option<bool>,
}

impl From<UserQuery> for SelectManyUsers {
    fn from(value: UserQuery) -> Self {
        Self {
            id: value.id,
            email: value.email,
            name: value.name,
            surname: value.surname,
            admin: value.admin,
            disabled: value.disabled,
            pagination: Some(Pagination::default_pagination(value.page)),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserUpdateFormAdmin {
    pub csrf_token: CsrfToken,
    pub id: Id,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub email: Option<String>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "empty_string_is_none")]
    pub surname: Option<String>,
    #[serde(default)]
    pub admin: bool,
    #[serde(default)]
    pub disabled: bool,
}

impl From<UserUpdateFormAdmin> for UserUpdate {
    fn from(value: UserUpdateFormAdmin) -> Self {
        Self {
            id: value.id,
            email: value.email,
            name: value.name,
            surname: value.surname,
            admin: Some(value.admin),
            disabled: Some(value.disabled),
        }
    }
}

impl CsrfGuarded for UserUpdateFormAdmin {
    fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserUpdatePasswordFormAdmin {
    pub csrf_token: CsrfToken,
    pub id: Id,
    pub new_password: String,
    pub confirm_password: String,
}

impl CsrfGuarded for UserUpdatePasswordFormAdmin {
    fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct UserCreateForm {
    pub csrf_token: CsrfToken,
    pub email: String,
    pub name: String,
    pub surname: String,
    #[serde(default)]
    pub admin: bool,
    pub password: String,
    pub confirm_password: String,
}

impl CsrfGuarded for UserCreateForm {
    fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct UserUpdateForm {
    pub csrf_token: CsrfToken,
    pub email: String,
    pub name: String,
    pub surname: String,
}

impl CsrfGuarded for UserUpdateForm {
    fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserUpdatePasswordForm {
    pub csrf_token: CsrfToken,
    pub old_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

impl CsrfGuarded for UserUpdatePasswordForm {
    fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }
}

#[derive(Deserialize)]
pub struct UserLoginReturnURL {
    pub ret: Option<String>,
}

impl Display for UserLoginReturnURL {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ret={}", self.ret.as_ref().unwrap_or(&String::from("/")))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserLoginForm {
    pub csrf_token: CsrfToken,
    pub email: String,
    pub password: String,
    pub return_url: String,
}

impl CsrfGuarded for UserLoginForm {
    fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }
}