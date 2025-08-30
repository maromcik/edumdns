use crate::error::DbError;
use crate::models::{Device, Location, Probe, ProbeConfig, User};
use crate::repositories::common::{DbCreate, DbDelete, DbReadMany, DbReadOne, DbResult, DbResultMultiple, DbResultSingle, Id, Permission, SelectSingleById};
use crate::repositories::probe::models::{CreateProbe, CreateProbeConfig, SelectManyProbes, SelectSingleProbe, SelectSingleProbeConfig};
use crate::repositories::utilities::{no_permission_error, validate_permissions};
use crate::schema::group_probe_permission;
use crate::schema::group_user;
use crate::schema::probe;
use crate::schema::user;
use crate::schema::{location, probe_config};
use diesel::{BelongingToDsl, ExpressionMethods, JoinOnDsl, QueryDsl, SelectableHelper};
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
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

impl DbReadOne<SelectSingleProbe, (Probe, Vec<Device>, Vec<ProbeConfig>)> for PgProbeRepository {
    async fn read_one(&self, params: &SelectSingleProbe) -> DbResultSingle<(Probe, Vec<Device>, Vec<ProbeConfig>)> {
        let mut conn = self.pg_pool.get().await?;
        validate_permissions(&self.pg_pool, params, Permission::Read).await?;
        let probe_data = probe::table
            .find(params.id)
            .select(Probe::as_select())
            .first(&mut conn)
            .await?;
        let configs = self.get_probe_configs_no_auth(&params.id).await?;
        let devices = Device::belonging_to(&probe_data)
            .select(Device::as_select())
            .load(&mut conn)
            .await?;
        Ok((probe_data, devices, configs))
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
                .select((Option::<Location>::as_select(), Probe::as_select()))
                .load::<(Option<Location>, Probe)>(&mut conn)
                .await?);
        }

        let probes = query
            .inner_join(
                group_probe_permission::table.on(group_probe_permission::probe_id.eq(probe::id)),
            )
            .inner_join(
                group_user::table.on(group_user::group_id.eq(group_probe_permission::group_id)),
            )
            .filter(group_user::user_id.eq(params.user_id))
            .filter(group_probe_permission::permission.eq(Permission::Read))
            .left_outer_join(location::table)
            .select((Option::<Location>::as_select(), Probe::as_select()))
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

impl DbDelete<SelectSingleProbe, Probe> for PgProbeRepository {
    async fn delete(&self, params: &SelectSingleProbe) -> DbResultMultiple<Probe> {
        let mut conn = self.pg_pool.get().await?;
        validate_permissions(&self.pg_pool, params, Permission::Delete).await?;
        diesel::delete(probe::table.find(params.id))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl PgProbeRepository {
    pub async fn forget(&self, params: &SelectSingleProbe) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        validate_permissions(&self.pg_pool, params, Permission::Forget).await?;

        diesel::update(probe::table.find(params.id))
            .set(probe::adopted.eq(false))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn adopt(&self, params: &SelectSingleProbe) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        validate_permissions(&self.pg_pool, params, Permission::Adopt).await?;
        diesel::update(probe::table.find(params.id))
            .set(probe::adopted.eq(true))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn get_probe_configs_no_auth(&self, params: &Uuid) -> DbResultMultiple<ProbeConfig> {
        let mut conn = self.pg_pool.get().await?;

        probe_config::table
            .filter(probe_config::probe_id.eq(params))
            .select(ProbeConfig::as_select())
            .load(&mut conn)
            .await
            .map_err(DbError::from)
    }

    pub async fn get_probe_configs(&self, params: &SelectSingleProbe) -> DbResultMultiple<ProbeConfig> {
        validate_permissions(&self.pg_pool, params, Permission::ModifyConfig).await?;
        self.get_probe_configs_no_auth(&params.id).await
    }

    pub async fn delete_probe_config(&self, params: &SelectSingleProbeConfig) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        validate_permissions(&self.pg_pool, &SelectSingleProbe::new(params.user_id, params.probe_id), Permission::ModifyConfig).await?;
        diesel::delete(probe_config::table
            .find(params.id))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn create_probe_config(&self, params: &CreateProbeConfig, user_id: Id) -> DbResult<()> {
        validate_permissions(&self.pg_pool, &SelectSingleProbe::new(user_id, params.probe_id), Permission::ModifyConfig).await?;
        diesel::insert_into(probe_config::table)
            .values(params)
            .execute(&mut self.pg_pool.get().await?)
            .await?;
        Ok(())
    }


    pub async fn check_permissions_for_restart(&self, params: &SelectSingleProbe) -> DbResult<()> {
        validate_permissions(&self.pg_pool, params, Permission::Restart).await?;
        Ok(())
    }
}
