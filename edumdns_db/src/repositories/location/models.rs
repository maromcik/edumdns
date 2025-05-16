// use crate::models::{ContentCategory, ContentType};
// use crate::repositories::common::Pagination;
// use chrono::NaiveDate;
// use diesel::{AsChangeset, Insertable};
// use serde::{Deserialize, Serialize};
// use uuid::Uuid;
// 
// #[derive(Serialize, Deserialize)]
// pub struct SelectManyFilter {
//     pub content_type: Option<ContentType>,
//     pub content_category: Option<ContentCategory>,
//     pub length_from: Option<i32>,
//     pub length_to: Option<i32>,
//     pub pagination: Option<Pagination>,
// }
// 
// #[derive(Serialize, Deserialize, AsChangeset, Insertable)]
// #[diesel(table_name = crate::schema::content)]
// pub struct NewContent {
//     pub parent_content_id: Option<Uuid>,
//     pub title: String,
//     pub description: String,
//     pub content_type: ContentType,
//     pub content_category: ContentCategory,
//     pub length: i32,
//     pub released_at: NaiveDate,
// }
