use serde::Serialize;

// #[template(path = "error.html")]
#[derive(Serialize)]
pub struct GenericError {
    pub code: u16,
    pub status_code: String,
    pub description: String,
}
