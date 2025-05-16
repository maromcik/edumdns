// use crate::errors::DatabaseError;
// use diesel::pg::*;
// use diesel::r2d2::{ConnectionManager, Pool};
// use diesel::{ExpressionMethods, QueryDsl, RunQueryDsl, SelectableHelper};
// use std::ops::DerefMut;
// use uuid::Uuid;
// 
// use crate::models::Content;
// use crate::repositories::content::models::{NewContent, SelectManyFilter};
// use crate::schema;
// use crate::schema::content::{content_category, content_type, deleted_at, length};
// 
// pub trait ContentRepository {
//     fn get_content(&self, content_id: Uuid) -> Result<Content, DatabaseError>;
//     fn get_contents(&self, filters: SelectManyFilter) -> Result<Vec<Content>, DatabaseError>;
//     fn create_content(&self, new_content: NewContent) -> Result<Content, DatabaseError>;
// }
// 
// #[derive(Clone)]
// pub struct PgContentRepository {
//     pg_pool: Pool<ConnectionManager<PgConnection>>,
// }
// 
// impl PgContentRepository {
//     pub fn new(pg_pool: Pool<ConnectionManager<PgConnection>>) -> Self {
//         Self { pg_pool }
//     }
// }
// 
// impl ContentRepository for PgContentRepository {
//     fn get_content(&self, content_id: Uuid) -> Result<Content, DatabaseError> {
//         let mut conn = self.pg_pool.get()?;
//         let content = schema::content::dsl::content
//             .find(content_id)
//             .filter(deleted_at.is_null())
//             .select(Content::as_select())
//             .first(conn.deref_mut())?;
// 
//         Ok(content)
//     }
// 
//     fn get_contents(&self, filters: SelectManyFilter) -> Result<Vec<Content>, DatabaseError> {
//         let mut query = schema::content::dsl::content
//             .filter(deleted_at.is_null())
//             .order(schema::content::dsl::released_at.desc())
//             .into_boxed();
// 
//         if let Some(filter_content_type) = filters.content_type {
//             query = query.filter(content_type.eq(filter_content_type));
//         }
// 
//         if let Some(filter_content_category) = filters.content_category {
//             query = query.filter(content_category.eq(filter_content_category));
//         }
// 
//         if let Some(length_from) = filters.length_from {
//             query = query.filter(length.ge(length_from));
//         }
// 
//         if let Some(length_to) = filters.length_to {
//             query = query.filter(length.le(length_to));
//         }
// 
//         if let Some(pagination) = filters.pagination {
//             query = query.limit(pagination.limit.unwrap_or(i64::MAX));
//             query = query.offset(pagination.offset.unwrap_or(0));
//         }
// 
//         let mut conn = self.pg_pool.get()?;
//         let contents = query.load::<Content>(conn.deref_mut())?;
// 
//         Ok(contents)
//     }
// 
//     fn create_content(&self, new_content: NewContent) -> Result<Content, DatabaseError> {
//         let mut conn = self.pg_pool.get()?;
//         let content = diesel::insert_into(schema::content::table)
//             .values(&new_content)
//             .returning(Content::as_returning())
//             .get_result(conn.deref_mut())?;
// 
//         Ok(content)
//     }
// }
