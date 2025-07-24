// use crate::error::DbError;
// use crate::models::Location;
// use crate::repositories::common::Id;
// use crate::repositories::location::models::{CreateLocation, SelectManyFilter};
// use std::ops::DerefMut;
//
// use crate::schema;
// use crate::schema::location::name;
// use diesel::result::Error;
// use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
// use diesel_async::AsyncPgConnection;
// use diesel_async::pooled_connection::deadpool::Pool;
// use diesel_async::scoped_futures::ScopedFutureExt;
// use diesel_async::{AsyncConnection, RunQueryDsl};
//
// pub trait LocationRepository {
//     async fn get_location(&self, location_id: Id) -> Result<Location, DbError>;
//     async fn get_locations(&self, filters: SelectManyFilter) -> Result<Vec<Location>, DbError>;
//     async fn create_location(&self, location_create: CreateLocation) -> Result<Location, DbError>;
// }
//
// #[derive(Clone)]
// pub struct PgLocationRepository {
//     pg_pool: Pool<AsyncPgConnection>,
// }
//
// impl PgLocationRepository {
//     pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
//         Self { pg_pool }
//     }
// }
//
// impl LocationRepository for PgLocationRepository {
//     async fn get_location(&self, location_id: Id) -> Result<Location, DbError> {
//         let mut conn = self.pg_pool.get().await?;
//         let location = schema::location::dsl::location
//             .find(location_id)
//             .select(Location::as_select())
//             .first(&mut conn)
//             .await?;
//
//         Ok(location)
//     }
//
//     async fn get_locations(&self, filters: SelectManyFilter) -> Result<Vec<Location>, DbError> {
//         let mut query = schema::location::dsl::location.into_boxed();
//
//         if let Some(n) = filters.name {
//             query = query.filter(name.eq(n));
//         }
//
//         if let Some(pagination) = filters.pagination {
//             query = query.limit(pagination.limit.unwrap_or(i64::MAX));
//             query = query.offset(pagination.offset.unwrap_or(0));
//         }
//
//         let mut conn = self.pg_pool.get().await?;
//         let users = query.load::<Location>(&mut conn).await?;
//
//         Ok(users)
//     }
//
//     async fn create_location(&self, location_create: CreateLocation) -> Result<Location, DbError> {
//         let mut conn = self.pg_pool.get().await?;
//         let location = conn
//             .deref_mut()
//             .transaction::<_, Error, _>(|c| {
//                 async move {
//                     diesel::insert_into(schema::location::table)
//                         .values(&location_create)
//                         .returning(Location::as_returning())
//                         .get_result(c)
//                         .await
//                 }
//                 .scope_boxed()
//             })
//             .await?;
//
//         Ok(location)
//     }
// }
