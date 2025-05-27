use crate::error::DbError;
use crate::models::{Location, Probe, User};
use crate::repositories::common::{DbCreate, DbReadMany, DbReadOne, DbResult, DbResultMultiple, DbResultSingle};
use crate::repositories::probe::models::{CreateProbe, SelectManyFilter};
use crate::schema;
use crate::schema::location::dsl::location;
use crate::schema::user::dsl::user;
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::RunQueryDsl;
use diesel_async::AsyncPgConnection;
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
    async fn read_many(&self, params: &SelectManyFilter) -> DbResultMultiple<(Location, User, Probe)> {
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

        if let Some(q) = &params.port {
            query = query.filter(port.eq(q));
        }

        if let Some(q) = &params.owner_id {
            query = query.filter(owner_id.eq(q));
        }

        if let Some(q) = &params.location_id {
            query = query.filter(location_id.eq(q));
        }

        if let Some(q) = &params.vlan {
            query = query.filter(vlan.eq(q));
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
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl PgProbeRepository {
    async fn forget(&self, params: &Uuid) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        diesel::update(probe.find(params)).set(adopted.eq(false)).execute(&mut conn).await?;
        Ok(())
    }
}