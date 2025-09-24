use serde::Serialize;

#[derive(Serialize)]
pub struct IndexTemplate {
    pub logged_in: bool,
    pub is_admin: bool,
    pub has_groups: bool,
}
