// use crate::errors::DatabaseError;
// use diesel::pg::*;
// use diesel::r2d2::{ConnectionManager, Pool};
// use diesel::{Connection, ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper};
// use std::ops::DerefMut;
// use uuid::Uuid;
// 
// use crate::models::{Content, Review, User};
// use crate::repositories::review::models::{NewReview, SelectManyFilter};
// use crate::schema;
// use crate::schema::review::{content_id, deleted_at, user_id};
// 
// pub trait ReviewRepository {
//     fn get_review(&self, review_id: Uuid) -> Result<Review, DatabaseError>;
//     fn get_reviews(&self, filters: SelectManyFilter) -> Result<Vec<Review>, DatabaseError>;
//     fn create_review(&self, new_review: NewReview) -> Result<Review, DatabaseError>;
// }
// 
// #[derive(Clone)]
// pub struct PgReviewRepository {
//     pg_pool: Pool<ConnectionManager<PgConnection>>,
// }
// 
// impl PgReviewRepository {
//     pub fn new(pg_pool: Pool<ConnectionManager<PgConnection>>) -> Self {
//         Self { pg_pool }
//     }
// }
// 
// impl ReviewRepository for PgReviewRepository {
//     fn get_review(&self, review_id: Uuid) -> Result<Review, DatabaseError> {
//         let mut conn = self.pg_pool.get()?;
//         let review = schema::review::dsl::review
//             .find(review_id)
//             .filter(deleted_at.is_null())
//             .select(Review::as_select())
//             .first(conn.deref_mut())?;
// 
//         Ok(review)
//     }
// 
//     fn get_reviews(&self, filters: SelectManyFilter) -> Result<Vec<Review>, DatabaseError> {
//         let mut query = schema::review::dsl::review
//             .filter(deleted_at.is_null())
//             .order(schema::review::dsl::created_at.desc())
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
//         let users = query.load::<Review>(conn.deref_mut())?;
// 
//         Ok(users)
//     }
// 
//     fn create_review(&self, new_review: NewReview) -> Result<Review, DatabaseError> {
//         let mut conn = self.pg_pool.get()?;
//         let review = conn.deref_mut().transaction(|conn| {
//             schema::content::dsl::content
//                 .find(new_review.content_id)
//                 .filter(schema::content::deleted_at.is_null())
//                 .select(Content::as_select())
//                 .first(conn)?;
// 
//             schema::user::dsl::user
//                 .find(new_review.user_id)
//                 .filter(schema::user::deleted_at.is_null())
//                 .select(User::as_select())
//                 .first(conn)?;
// 
//             diesel::insert_into(schema::review::table)
//                 .values(&new_review)
//                 .returning(Review::as_returning())
//                 .get_result(conn)
//         });
// 
//         if let Err(diesel::result::Error::NotFound) = review {
//             return Err(DatabaseError::BrokenConstraint);
//         }
// 
//         Ok(review?)
//     }
// }
