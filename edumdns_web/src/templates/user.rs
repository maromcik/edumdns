use crate::forms::user::UserQuery;
use edumdns_db::models::User;
use edumdns_db::repositories::common::Permissions;
use edumdns_db::repositories::utilities::WEAK_PASSWORD_MESSAGE;
use serde::Serialize;

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
