use serde::Serialize;
use edumdns_db::models::Group;

#[derive(Serialize)]
pub struct GroupTemplate {
    pub logged_in: bool,
    pub groups: Vec<Group>
}