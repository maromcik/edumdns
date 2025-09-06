use serde::Serialize;

pub mod device;
pub mod error;
pub mod group;
pub mod index;
pub mod packet;
pub mod probe;
pub mod user;

#[derive(Serialize)]
pub struct PageInfo {
    pub page: i64,
    pub total_pages: i64,
}

impl PageInfo {
    pub fn new(page: i64, total_pages: i64) -> Self {
        Self { page, total_pages }
    }
}