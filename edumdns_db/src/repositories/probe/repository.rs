use crate::error::DbError;
use crate::models::{Location, Probe, ProbeConfig, User};
use crate::repositories::common::{
    DbCreate, DbReadMany, DbReadOne, DbResult, DbResultMultiple, DbResultSingle,
};
use crate::repositories::probe::models::{CreateProbe, SelectManyFilter};
use crate::schema;
use crate::schema::location::dsl::location;
use crate::schema::probe_config::dsl::probe_config;
use crate::schema::probe_config::probe_id;
use crate::schema::user::dsl::user;
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use schema::probe::dsl::*;
use uuid::Uuid;

#[derive(Clone)]
pub struct PgProbeRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgProbeRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }
}

impl DbReadOne<Uuid, Probe> for PgProbeRepository {
    async fn read_one(&self, params: &Uuid) -> DbResultSingle<Probe> {
        let mut conn = self.pg_pool.get().await?;
        probe
            .find(params)
            .select(Probe::as_select())
            .first(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbReadMany<SelectManyFilter, (Location, User, Probe)> for PgProbeRepository {
    async fn read_many(
        &self,
        params: &SelectManyFilter,
    ) -> DbResultMultiple<(Location, User, Probe)> {
        let mut query = probe.into_boxed();

        if let Some(q) = &params.adopted {
            query = query.filter(adopted.eq(q));
        }

        if let Some(q) = &params.mac {
            query = query.filter(mac.eq(q));
        }

        if let Some(q) = &params.ip {
            query = query.filter(ip.eq(q));
        }

        if let Some(q) = &params.owner_id {
            query = query.filter(owner_id.eq(q));
        }

        if let Some(q) = &params.location_id {
            query = query.filter(location_id.eq(q));
        }

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let probes = query
            .inner_join(location)
            .inner_join(user)
            .select((Location::as_select(), User::as_select(), Probe::as_select()))
            .load::<(Location, User, Probe)>(&mut conn)
            .await?;

        Ok(probes)
    }
}

impl DbCreate<CreateProbe, Probe> for PgProbeRepository {
    async fn create(&self, data: &CreateProbe) -> DbResultSingle<Probe> {
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(schema::probe::table)
            .values(data)
            .returning(Probe::as_returning())
            .on_conflict(id)
            .do_update()
            .set((mac.eq(data.mac), ip.eq(data.ip)))
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl PgProbeRepository {
    pub async fn forget(&self, params: &Uuid) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        diesel::update(probe.find(params))
            .set(adopted.eq(false))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn adopt(&self, params: &Uuid) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        diesel::update(probe.find(params))
            .set(adopted.eq(true))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn get_probe_config(&self, params: &Uuid) -> DbResultMultiple<ProbeConfig> {
        let mut conn = self.pg_pool.get().await?;

        probe_config
            .filter(probe_id.eq(params))
            .select(ProbeConfig::as_select())
            .load(&mut conn)
            .await
            .map_err(DbError::from)
    }
}
