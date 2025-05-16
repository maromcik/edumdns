use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct Pagination {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

impl Pagination {
    pub fn new(limit: Option<i64>, offset: Option<i64>) -> Self {
        Self { limit, offset }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug)]
pub struct GetById {
    pub id: Id
}

impl GetById {
    pub fn new(id: Id) -> Self {
        Self { id }
    }
}


pub type Id = i64;