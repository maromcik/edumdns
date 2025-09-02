use edumdns_db::repositories::common::{Id, Pagination};
use serde::{Deserialize, Serialize};
use edumdns_db::repositories::user::models::SelectManyUsers;

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct UserCreateForm {
    pub email: String,
    pub password: String,
    pub confirm_password: String,
    pub name: String,
    pub surname: String,
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

#[derive(Debug, Clone, Deserialize)]
pub struct UserLoginForm {
    pub email: String,
    pub password: String,
    pub return_url: String,
}

#[derive(Serialize, Deserialize)]
pub struct UserQuery {
    pub email: Option<String>,
    pub name: Option<String>,
    pub surname: Option<String>,
    pub admin: Option<bool>,
    pub deleted: Option<bool>,
    pub page: Option<i64>,
}

impl From<UserQuery> for SelectManyUsers {
    fn from(value: UserQuery) -> Self {
        Self {
            email: value.email,
            name: value.name,
            surname: value.surname,
            admin: value.admin,
            deleted: value.deleted,
            pagination: Some(Pagination::default_pagination(value.page)),
        }
    }
}

