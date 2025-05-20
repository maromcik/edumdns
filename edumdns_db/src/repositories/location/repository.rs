use crate::error::DbError;
use crate::models::{Group, Location};
use crate::repositories::common::Id;
use crate::repositories::location::models::{CreateLocation, SelectManyFilter};
use crate::schema;
use crate::schema::location::name;
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use schema::location::dsl::*;
use crate::repositories::group::models::CreateGroup;

pub trait LocationRepository {
    async fn get_location(&self, location_id: Id) -> Result<Location, DbError>;
    async fn get_locations(&self, filters: SelectManyFilter) -> Result<Vec<Location>, DbError>;
    async fn create_location(&self, location_create: CreateLocation) -> Result<Location, DbError>;
    async fn update_group(&self, group_id: Id, group_update: CreateGroup) -> Result<Group, DbError>;

    async fn delete_location(&self, location_id: Id) -> Result<Group, DbError>;

}

#[derive(Clone)]
pub struct PgLocationRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgLocationRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }
}

impl LocationRepository for PgLocationRepository {
    async fn get_location(&self, location_id: Id) -> Result<Location, DbError> {
        let mut conn = self.pg_pool.get().await?;
        location
            .find(location_id)
            .select(Location::as_select())
            .first(&mut conn)
            .await
            .map_err(DbError::from)
    }

    async fn get_locations(&self, filters: SelectManyFilter) -> Result<Vec<Location>, DbError> {
        let mut query = location.into_boxed();

        if let Some(n) = filters.name {
            query = query.filter(name.eq(n));
        }

        if let Some(pagination) = filters.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let locations = query.load::<Location>(&mut conn).await?;

        Ok(locations)
    }

    async fn create_location(&self, location_create: CreateLocation) -> Result<Location, DbError> {
        let mut conn = self.pg_pool.get().await?;

        diesel::insert_into(schema::location::table)
            .values(&location_create)
            .returning(Location::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }

    async fn update_group(&self, group_id: Id, group_update: CreateGroup) -> Result<Group, DbError> {
        todo!()
    }

    async fn delete_location(&self, location_id: Id) -> Result<Group, DbError> {
        let mut conn = self.pg_pool.get().await?;
        diesel::delete(location.find(location_id)).get_result(&mut conn).await.map_err(DbError::from)
    }
}
