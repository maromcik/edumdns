// use crate::errors::DatabaseError;
// use diesel::pg::*;
// use diesel::r2d2::{ConnectionManager, Pool};
// use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper};
// use std::ops::DerefMut;
// use uuid::Uuid;
// 
// use crate::models::{Content, Rating, User};
// use crate::repositories::rating::models::{NewRating, SelectManyFilter};
// use crate::schema;
// use crate::schema::rating::{content_id, deleted_at, user_id};
// 
// pub trait RatingRepository {
//     fn get_rating(&self, rating_id: Uuid) -> Result<Rating, DatabaseError>;
//     fn get_ratings(&self, filters: SelectManyFilter) -> Result<Vec<Rating>, DatabaseError>;
//     fn create_rating(&self, new_rating: NewRating) -> Result<Rating, DatabaseError>;
// }
// 
// #[derive(Clone)]
// pub struct PgRatingRepository {
//     pg_pool: Pool<ConnectionManager<PgConnection>>,
// }
// 
// impl PgRatingRepository {
//     pub fn new(pg_pool: Pool<ConnectionManager<PgConnection>>) -> Self {
//         Self { pg_pool }
//     }
// }
// 
// impl RatingRepository for PgRatingRepository {
//     fn get_rating(&self, rating_id: Uuid) -> Result<Rating, DatabaseError> {
//         let mut conn = self.pg_pool.get()?;
//         let rating = schema::rating::dsl::rating
//             .find(rating_id)
//             .filter(deleted_at.is_null())
//             .select(Rating::as_select())
//             .first(conn.deref_mut())?;
// 
//         Ok(rating)
//     }
// 
//     fn get_ratings(&self, filters: SelectManyFilter) -> Result<Vec<Rating>, DatabaseError> {
//         let mut query = schema::rating::dsl::rating
//             .filter(deleted_at.is_null())
//             .order(schema::rating::dsl::stars.desc())
//             .into_boxed();
// 
//         if let Some(content_uuid) = filters.content_id {
//             query = query.filter(content_id.eq(content_uuid));
//         }
// 
//         if let Some(user_uuid) = filters.user_id {
//             query = query.filter(user_id.eq(user_uuid));
//         }
// 
//         if let Some(pagination) = filters.pagination {
//             query = query.limit(pagination.limit.unwrap_or(i64::MAX));
//             query = query.offset(pagination.offset.unwrap_or(0));
//         }
// 
//         let mut conn = self.pg_pool.get()?;
//         let users = query.load::<Rating>(conn.deref_mut())?;
// 
//         Ok(users)
//     }
// 
//     fn create_rating(&self, new_rating: NewRating) -> Result<Rating, DatabaseError> {
//         let mut conn = self.pg_pool.get()?;
//         let rating = conn.deref_mut().transaction(|conn| {
//             schema::content::dsl::content
//                 .find(new_rating.content_id)
//                 .filter(schema::content::deleted_at.is_null())
//                 .select(Content::as_select())
//                 .first(conn)?;
// 
//             schema::user::dsl::user
//                 .find(new_rating.user_id)
//                 .filter(schema::user::deleted_at.is_null())
//                 .select(User::as_select())
//                 .first(conn)?;
// 
//             diesel::insert_into(schema::rating::table)
//                 .values(&new_rating)
//                 .returning(Rating::as_returning())
//                 .get_result(conn)
//         });
// 
//         if let Err(diesel::result::Error::NotFound) = rating {
//             return Err(DatabaseError::BrokenConstraint);
//         }
// 
//         Ok(rating?)
//     }
// }
