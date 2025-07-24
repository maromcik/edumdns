use crate::error::DbError;
use crate::models::Location;
use crate::repositories::common::{
    DbCreate, DbDelete, DbReadMany, DbReadOne, DbResultMultiple, DbResultSingle, Id,
};
use crate::repositories::location::models::{CreateLocation, SelectManyFilter};
use crate::schema;
use crate::schema::location::name;
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use schema::location::dsl::*;

#[derive(Clone)]
pub struct PgLocationRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgLocationRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }
}

impl DbReadOne<Id, Location> for PgLocationRepository {
    async fn read_one(&self, params: &Id) -> DbResultSingle<Location> {
        let mut conn = self.pg_pool.get().await?;
        location
            .find(params)
            .select(Location::as_select())
            .first(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbReadMany<SelectManyFilter, Location> for PgLocationRepository {
    async fn read_many(&self, params: &SelectManyFilter) -> DbResultMultiple<Location> {
        let mut query = location.into_boxed();

        if let Some(n) = &params.name {
            query = query.filter(name.eq(n));
        }

        if let Some(pagination) = &params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let locations = query.load::<Location>(&mut conn).await?;

        Ok(locations)
    }
}

impl DbCreate<CreateLocation, Location> for PgLocationRepository {
    async fn create(&self, data: &CreateLocation) -> DbResultSingle<Location> {
        let mut conn = self.pg_pool.get().await?;

        diesel::insert_into(schema::location::table)
            .values(data)
            .returning(Location::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbDelete<Id, Location> for PgLocationRepository {
    async fn delete(&self, params: &Id) -> DbResultMultiple<Location> {
        let mut conn = self.pg_pool.get().await?;
        diesel::delete(location.find(params))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }
}
