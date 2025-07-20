use serde::Serialize;

// #[template(path = "error.html")]
#[derive(Serialize)]
pub struct GenericError {
    pub code: String,
    pub description: String,
}
