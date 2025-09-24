use edumdns_db::repositories::common::{Id, Pagination};
use edumdns_db::repositories::user::models::{SelectManyUsers, UserUpdate};
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use edumdns_db::repositories::utilities::empty_string_is_none;

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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct UserUpdateFormAdmin {
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

#[derive(Deserialize, Debug, Clone)]
pub struct UserCreateForm {
    pub email: String,
    pub name: String,
    pub surname: String,
    pub admin: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct UserUpdateForm {
    pub email: String,
    pub name: String,
    pub surname: String,
}
#[derive(Debug, Clone, Deserialize)]
pub struct UserUpdatePasswordForm {
    pub old_password: String,
    pub new_password: String,
    pub confirm_password: String,
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
    pub email: String,
    pub password: String,
    pub return_url: String,
}

// #[derive(Serialize, Deserialize)]
// pub struct UserQuery {
//     pub email: Option<String>,
//     pub name: Option<String>,
//     pub surname: Option<String>,
//     pub admin: Option<bool>,
//     pub deleted: Option<bool>,
//     pub page: Option<i64>,
// }

