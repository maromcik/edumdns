// use crate::repositories::common::Pagination;
// use diesel::{AsChangeset, Insertable};
// use serde::{Deserialize, Serialize};
// use uuid::Uuid;
// 
// #[derive(Serialize, Deserialize)]
// pub struct SelectManyFilter {
//     pub content_id: Option<Uuid>,
//     pub user_id: Option<Uuid>,
//     pub pagination: Option<Pagination>,
// }
// 
// #[derive(Serialize, Deserialize, AsChangeset, Insertable)]
// #[diesel(table_name = crate::schema::review)]
// pub struct NewReview {
//     pub content_id: Uuid,
//     pub user_id: Uuid,
//     pub title: Option<String>,
//     pub content: String,
// }
