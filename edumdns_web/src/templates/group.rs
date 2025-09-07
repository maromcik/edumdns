use edumdns_db::models::{Group, User};
use edumdns_db::repositories::common::{Id, Permissions};
use serde::Serialize;
use crate::forms::group::GroupQuery;

#[derive(Serialize)]
pub struct GroupTemplate {
    pub logged_in: bool,
    pub is_admin: bool,
    pub permissions: Permissions,
    pub groups: Vec<Group>,
    pub filters: GroupQuery
}

#[derive(Serialize)]
pub struct GroupDetailTemplate {
    pub logged_in: bool,
    pub is_admin: bool,
    pub permissions: Permissions,
    pub group: Group,
}

#[derive(Serialize)]
pub struct GroupDetailUsersTemplate {
    pub users: Vec<User>,
    pub group_id: Id,
}
