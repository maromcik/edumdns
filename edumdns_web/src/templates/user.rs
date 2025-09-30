use crate::forms::user::UserQuery;
use edumdns_db::models::User;
use edumdns_db::repositories::common::Permissions;
use edumdns_db::repositories::utilities::WEAK_PASSWORD_MESSAGE;
use serde::Serialize;
use edumdns_db::repositories::user::models::UserDisplay;

#[derive(Serialize)]
pub struct UserTemplate {
    pub users: Vec<User>,
    pub user: UserDisplay,
    pub filters: UserQuery,
}

#[derive(Serialize)]
pub struct UserDetailTemplate{
    pub user: UserDisplay,
    pub target_user: UserDisplay,
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
}

impl UserManagePasswordTemplate {
    pub fn weak_password() -> Self {
        Self {
            success: false,
            message: WEAK_PASSWORD_MESSAGE.to_owned(),
        }
    }
}

#[derive(Serialize)]
pub struct UserManageProfileTemplate {
    pub user: UserDisplay,
    pub message: String,
    pub success: bool,
}

#[derive(Serialize)]
pub struct UserManageProfileUserFormTemplate {
    pub user: UserDisplay,
    pub message: String,
    pub success: bool,
}
