use crate::forms::group::GroupQuery;
use edumdns_db::models::{Group, User};
use edumdns_db::repositories::user::models::UserDisplay;
use serde::Serialize;

#[derive(Serialize)]
pub struct GroupTemplate {
    pub user: UserDisplay,
    pub groups: Vec<Group>,
    pub filters: GroupQuery,
}

#[derive(Serialize)]
pub struct GroupDetailTemplate {
    pub user: UserDisplay,
    pub users: Vec<User>,
    pub group: Group,
}

#[derive(Serialize)]
pub struct GroupDetailUsersTemplate {
    pub users: Vec<User>,
}
