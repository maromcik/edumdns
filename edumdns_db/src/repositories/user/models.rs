// use diesel::{AsChangeset, Insertable};
// use serde::Deserialize;
// 
// #[derive(AsChangeset, Insertable, Deserialize)]
// #[diesel(table_name = crate::schema::user)]
// pub struct NewUser {
//     pub username: String,
//     pub email: String,
// }
// 
// #[derive(AsChangeset, Insertable, Deserialize)]
// #[diesel(table_name = crate::schema::user)]
// pub struct PartialUser {
//     pub username: Option<String>,
//     pub email: Option<String>,
// }
// 
// impl From<NewUser> for PartialUser {
//     fn from(value: NewUser) -> Self {
//         Self {
//             username: Some(value.username),
//             email: Some(value.email),
//         }
//     }
// }
