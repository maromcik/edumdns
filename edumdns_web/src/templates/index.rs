use serde::Serialize;

#[derive(Serialize)]
pub struct IndexTemplate {
    pub logged_in: bool,
}
