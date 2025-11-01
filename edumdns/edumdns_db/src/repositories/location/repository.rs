use crate::error::DbError;
use crate::models::Location;
use crate::repositories::common::{
    DbCreate, DbDataPerm, DbDelete, DbReadMany, DbReadOne, DbResultMultiple, DbResultMultiplePerm,
    DbResultSingle, DbResultSinglePerm,
};
use crate::repositories::location::models::{CreateLocation, SelectManyFilter};
use crate::schema::location;
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::Id;
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
        let l = location::table
            .find(params)
            .select(Location::as_select())
            .first(&mut conn)
            .await?;
        Ok(l)
    }

    async fn read_one_auth(&self, params: &Id, _user_id: &Id) -> DbResultSinglePerm<Location> {
        let l = self.read_one(params).await?;
        Ok(DbDataPerm::new(l, (false, vec![])))
    }
}

impl DbReadMany<SelectManyFilter, Location> for PgLocationRepository {
    async fn read_many(&self, params: &SelectManyFilter) -> DbResultMultiple<Location> {
        let mut query = location::table.into_boxed();

        if let Some(n) = &params.name {
            query = query.filter(location::name.eq(n));
        }

        if let Some(pagination) = &params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let locations = query.load::<Location>(&mut conn).await?;

        Ok(locations)
    }
    async fn read_many_auth(
        &self,
        params: &SelectManyFilter,
        _user_id: &Id,
    ) -> DbResultMultiplePerm<Location> {
        let locations = self.read_many(params).await?;
        Ok(DbDataPerm::new(locations, (false, vec![])))
    }
}

impl DbCreate<CreateLocation, Location> for PgLocationRepository {
    async fn create(&self, data: &CreateLocation) -> DbResultSingle<Location> {
        let mut conn = self.pg_pool.get().await?;

        diesel::insert_into(location::table)
            .values(data)
            .returning(Location::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
    async fn create_auth(&self, data: &CreateLocation, _user_id: &Id) -> DbResultSingle<Location> {
        self.create(data).await
    }
}

impl DbDelete<Id, Location> for PgLocationRepository {
    async fn delete(&self, params: &Id) -> DbResultMultiple<Location> {
        let mut conn = self.pg_pool.get().await?;
        diesel::delete(location::table.find(params))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }

    async fn delete_auth(&self, params: &Id, _user_id: &Id) -> DbResultMultiple<Location> {
        self.delete(params).await
    }
}
