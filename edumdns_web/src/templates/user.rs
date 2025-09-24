use edumdns_db::models::{Group, User};
use serde::Serialize;
use edumdns_db::repositories::common::Permissions;
use crate::forms::group::GroupQuery;
use crate::forms::user::UserQuery;

const WEAK_PASSWORD_MESSAGE: &str = "Weak Password! Must contain at least one char from: {lower, upper, number, special} and be at least 6 characters long.";

#[derive(Serialize)]
pub struct UserTemplate {
    pub logged_in: bool,
    pub is_admin: bool,
    pub has_groups: bool,
    pub permissions: Permissions,
    pub users: Vec<User>,
    pub filters: UserQuery,
}

#[derive(Serialize)]
pub struct UserDetailTemplate {
    pub logged_in: bool,
    pub is_admin: bool,
    pub has_groups: bool,
    pub permissions: Permissions,
    pub user: User,
}

#[derive(Serialize)]
pub struct LoginTemplate {
    pub message: String,
    pub return_url: String,
}

#[derive(Serialize)]
pub struct UserManagePasswordTemplate {
    pub message: String,
    pub success: bool,
    pub logged_in: bool,
}

impl UserManagePasswordTemplate {
    pub fn weak_password() -> Self {
        Self {
            success: false,
            message: WEAK_PASSWORD_MESSAGE.to_owned(),
            logged_in: false,
        }
    }
}

#[derive(Serialize)]
pub struct UserManageProfileTemplate<'a> {
    pub user: &'a User,
    pub message: String,
    pub success: bool,
    pub logged_in: bool,
    pub is_admin: bool,
    pub has_groups: bool,
}

#[derive(Serialize)]
pub struct UserManageProfileUserFormTemplate<'a> {
    pub user: &'a User,
    pub message: String,
    pub success: bool,
    pub logged_in: bool,
}

