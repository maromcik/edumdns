use crate::error::DbError;
use crate::models::{
    Device, Group, GroupProbePermission, Location, Permission, Probe, ProbeConfig, User,
};
use crate::repositories::common::{
    DbCreate, DbReadMany, DbReadOne, DbResult, DbResultMultiple, DbResultSingle,
};
use crate::repositories::probe::models::{CreateProbe, SelectManyProbes};
use crate::schema::group_probe_permission;
use crate::schema::group_user;
use crate::schema::permission;
use crate::schema::probe;
use crate::schema::user;
use crate::schema::{location, probe_config};
use diesel::associations::HasTable;
use diesel::{
    BelongingToDsl, ExpressionMethods, JoinOnDsl, QueryDsl, Queryable, Selectable, SelectableHelper,
};
use diesel::expression::array_comparison::AsInExpression;
use diesel::expression::AsExpression;
use diesel::internal::derives::multiconnection::BoxedQueryHelper;
use diesel::query_builder::AsQuery;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
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
        probe::table
            .find(params)
            .select(Probe::as_select())
            .first(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbReadMany<SelectManyProbes, (Option<Location>, Probe)> for PgProbeRepository {
    async fn read_many(
        &self,
        params: &SelectManyProbes,
    ) -> DbResultMultiple<(Option<Location>, Probe)> {
        let mut query = probe::table.into_boxed();

        if let Some(q) = &params.adopted {
            query = query.filter(probe::adopted.eq(q));
        }

        if let Some(q) = &params.mac {
            query = query.filter(probe::mac.eq(q));
        }

        if let Some(q) = &params.ip {
            query = query.filter(probe::ip.eq(q));
        }

        if let Some(q) = &params.owner_id {
            query = query.filter(probe::owner_id.eq(q));
        }

        if let Some(q) = &params.location_id {
            query = query.filter(probe::location_id.eq(q));
        }

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;

        let user_entry = user::table
            .find(params.user_id)
            .select(User::as_select())
            .first(&mut conn)
            .await?;

        if user_entry.admin {
            return Ok(query
                .left_outer_join(location::table)
                .left_outer_join(user::table)
                .select((
                    Option::<Location>::as_select(),
                    Probe::as_select(),
                ))
                .load::<(Option<Location>, Probe)>(&mut conn)
                .await?);
        }

        let probes = query
            .inner_join(group_probe_permission::table.on(group_probe_permission::probe_id.eq(probe::id)))
            .inner_join(group_user::table.on(group_user::group_id.eq(group_probe_permission::group_id)))
            .filter(group_user::user_id.eq(params.user_id))
            .inner_join(permission::table.on(permission::id.eq(group_probe_permission::permission_id)))
            .filter(permission::name.eq("read"))
            .left_outer_join(location::table)
            .left_outer_join(user::table)
            .select((
                Option::<Location>::as_select(),
                Probe::as_select(),
            ))
            .load::<(Option<Location>, Probe)>(&mut conn)
            .await?;



        Ok(probes)
    }
}

impl DbCreate<CreateProbe, Probe> for PgProbeRepository {
    async fn create(&self, data: &CreateProbe) -> DbResultSingle<Probe> {
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(probe::table)
            .values(data)
            .returning(Probe::as_returning())
            .on_conflict(probe::id)
            .do_update()
            .set((probe::mac.eq(data.mac), probe::ip.eq(data.ip)))
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl PgProbeRepository {
    pub async fn forget(&self, params: &Uuid) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        diesel::update(probe::table.find(params))
            .set(probe::adopted.eq(false))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn read_probe_and_devices(
        &self,
        params: &Uuid,
    ) -> DbResultSingle<(Probe, Vec<Device>)> {
        let mut conn = self.pg_pool.get().await?;
        let p = probe::table
            .find(params)
            .select(Probe::as_select())
            .get_result(&mut conn)
            .await?;

        let devices = Device::belonging_to(&p)
            .select(Device::as_select())
            .load(&mut conn)
            .await?;
        Ok((p, devices))
    }

    pub async fn adopt(&self, params: &Uuid) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        diesel::update(probe::table.find(params))
            .set(probe::adopted.eq(true))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn get_probe_config(&self, params: &Uuid) -> DbResultMultiple<ProbeConfig> {
        let mut conn = self.pg_pool.get().await?;

        probe_config::table
            .filter(probe_config::probe_id.eq(params))
            .select(ProbeConfig::as_select())
            .load(&mut conn)
            .await
            .map_err(DbError::from)
    }
}
