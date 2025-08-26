use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use crate::repositories::common::Pagination;

#[derive(Serialize, Deserialize)]
pub struct SelectManyFilter {
    pub email: Option<String>,
    pub name: Option<String>,
    pub surname: Option<String>,
    pub admin: Option<bool>,
    pub deleted: Option<bool>,
    pub pagination: Option<Pagination>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserLogin {
    pub email: String,
    pub password: String,
}

impl UserLogin {
    #[must_use]
    #[inline]
    pub fn new(email: &str, password_hash: &str) -> Self {
        Self {
            email: email.to_owned(),
            password: password_hash.to_owned(),
        }
    }
}