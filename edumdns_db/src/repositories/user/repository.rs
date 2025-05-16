// use crate::errors::DatabaseError;
// use diesel::pg::*;
// use diesel::r2d2::{ConnectionManager, Pool};
// use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper};
// use std::ops::DerefMut;
// use uuid::Uuid;
// 
// use crate::models::User;
// use crate::repositories::user::models::{NewUser, PartialUser};
// use crate::schema;
// use crate::schema::user::{deleted_at, id};
// 
// pub trait UserRepository {
//     fn get_user(&self, user_id: Uuid) -> Result<User, DatabaseError>;
//     fn create_user(&self, new_user: NewUser) -> Result<User, DatabaseError>;
//     fn edit_user(&self, user_id: Uuid, patch_user: PartialUser) -> Result<User, DatabaseError>;
//     fn delete_user(&self, user_id: Uuid) -> Result<(), DatabaseError>;
// }
// 
// #[derive(Clone)]
// pub struct PgUserRepository {
//     pg_pool: Pool<ConnectionManager<PgConnection>>,
// }
// 
// impl PgUserRepository {
//     pub fn new(pg_pool: Pool<ConnectionManager<PgConnection>>) -> Self {
//         Self { pg_pool }
//     }
// }
// 
// impl UserRepository for PgUserRepository {
//     fn get_user(&self, user_id: Uuid) -> Result<User, DatabaseError> {
//         let mut conn = self.pg_pool.get()?;
//         let user = schema::user::dsl::user
//             .find(user_id)
//             .filter(deleted_at.is_null())
//             .select(User::as_select())
//             .first(conn.deref_mut())?;
// 
//         Ok(user)
//     }
// 
//     fn create_user(&self, new_user: NewUser) -> Result<User, DatabaseError> {
//         let mut conn = self.pg_pool.get()?;
//         let user = diesel::insert_into(schema::user::table)
//             .values(&new_user)
//             .returning(User::as_returning())
//             .get_result(conn.deref_mut())?;
// 
//         Ok(user)
//     }
// 
//     fn edit_user(&self, user_id: Uuid, patch_user: PartialUser) -> Result<User, DatabaseError> {
//         let mut conn = self.pg_pool.get()?;
//         let user = diesel::update(schema::user::table)
//             .filter(id.eq(user_id))
//             .filter(deleted_at.is_null())
//             .set(patch_user)
//             .returning(User::as_returning())
//             .get_result(conn.deref_mut())?;
// 
//         Ok(user)
//     }
// 
//     fn delete_user(&self, user_id: Uuid) -> Result<(), DatabaseError> {
//         let time_now = chrono::offset::Utc::now();
//         let mut conn = self.pg_pool.get()?;
//         conn.deref_mut().transaction(|conn| {
//             let rows_affected = diesel::update(schema::user::table)
//                 .filter(id.eq(user_id))
//                 .filter(deleted_at.is_null())
//                 .set(deleted_at.eq(time_now))
//                 .execute(conn)?;
// 
//             if rows_affected == 0 {
//                 return Err(diesel::NotFound);
//             }
// 
//             diesel::update(schema::review::table)
//                 .filter(schema::review::user_id.eq(user_id))
//                 .filter(schema::review::deleted_at.is_null())
//                 .set(schema::review::deleted_at.eq(time_now))
//                 .execute(conn)?;
// 
//             diesel::update(schema::rating::table)
//                 .filter(schema::rating::user_id.eq(user_id))
//                 .filter(schema::rating::deleted_at.is_null())
//                 .set(schema::rating::deleted_at.eq(time_now))
//                 .execute(conn)?;
// 
//             Ok(())
//         })?;
// 
//         Ok(())
//     }
// }
