use crate::error::DbError;
use crate::models::{GroupProbePermission, Location, Probe, ProbeConfig, User};
use crate::repositories::common::{
    DbCreate, DbDataPerm, DbDelete, DbReadMany, DbReadOne, DbResult, DbResultMultiple,
    DbResultMultiplePerm, DbResultSingle, DbResultSinglePerm, DbUpdate, Id, Permission,
};
use crate::repositories::probe::models::{
    AlterProbePermission, CreateProbe, CreateProbeConfig, SelectManyProbes,
    SelectSingleProbeConfig, UpdateProbe,
};
use crate::repositories::utilities::{validate_admin, validate_permissions, validate_user};
use crate::schema::group_user;
use crate::schema::probe;
use crate::schema::probe::BoxedQuery;
use crate::schema::user;
use crate::schema::{device, group_probe_permission};
use crate::schema::{location, probe_config};
use diesel::pg::Pg;
use diesel::{
    BoolExpressionMethods, ExpressionMethods, JoinOnDsl, PgNetExpressionMethods,
    PgTextExpressionMethods, QueryDsl, SelectableHelper,
};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone)]
pub struct PgProbeRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgProbeRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }

    pub fn build_select_many_query<'a>(params: &'a SelectManyProbes) -> BoxedQuery<'a, Pg> {
        let mut query = probe::table.into_boxed();

        if let Some(q) = &params.id {
            query = query.filter(probe::id.eq(q));
        }

        if let Some(q) = &params.adopted {
            query = query.filter(probe::adopted.eq(q));
        }

        if let Some(q) = &params.mac {
            query = query.filter(probe::mac.eq(q));
        }

        if let Some(q) = &params.ip {
            query = query.filter(probe::ip.is_contained_by_or_eq(q));
        }

        if let Some(q) = &params.owner_id {
            query = query.filter(probe::owner_id.eq(q));
        }

        if let Some(q) = &params.location_id {
            query = query.filter(probe::location_id.eq(q));
        }

        if let Some(q) = &params.name {
            query = query.filter(probe::name.ilike(format!("%{q}%")))
        }

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }
        query
    }
}

impl DbReadOne<Uuid, (Probe, Vec<ProbeConfig>)> for PgProbeRepository {
    async fn read_one(&self, params: &Uuid) -> DbResultSingle<(Probe, Vec<ProbeConfig>)> {
        let mut conn = self.pg_pool.get().await?;
        let probe_data = probe::table
            .find(params)
            .select(Probe::as_select())
            .first(&mut conn)
            .await?;
        let configs = self.get_probe_configs_no_auth(params).await?;
        Ok((probe_data, configs))
    }

    async fn read_one_auth(
        &self,
        params: &Uuid,
        user_id: &Id,
    ) -> DbResultSinglePerm<(Probe, Vec<ProbeConfig>)> {
        let permissions =
            validate_permissions(&self.pg_pool, user_id, params, Permission::Read).await?;
        let data = self.read_one(params).await?;
        Ok(DbDataPerm::new(data, permissions))
    }
}

impl DbReadMany<SelectManyProbes, (Option<Location>, Probe)> for PgProbeRepository {
    async fn read_many(
        &self,
        params: &SelectManyProbes,
    ) -> DbResultMultiple<(Option<Location>, Probe)> {
        let mut conn = self.pg_pool.get().await?;
        let query = PgProbeRepository::build_select_many_query(params);

        let probes = query
            .left_outer_join(location::table)
            .order_by(probe::ip.asc())
            .select((Option::<Location>::as_select(), Probe::as_select()))
            .load::<(Option<Location>, Probe)>(&mut conn)
            .await?;

        Ok(probes)
    }

    async fn read_many_auth(
        &self,
        params: &SelectManyProbes,
        user_id: &Id,
    ) -> DbResultMultiplePerm<(Option<Location>, Probe)> {
        let mut conn = self.pg_pool.get().await?;
        let query = PgProbeRepository::build_select_many_query(params);

        let user_entry = user::table
            .find(user_id)
            .select(User::as_select())
            .first(&mut conn)
            .await?;

        validate_user(&user_entry)?;

        if user_entry.admin {
            let probes = self.read_many(params).await?;
            return Ok(DbDataPerm::new(
                probes,
                (true, vec![GroupProbePermission::full()]),
            ));
        }

        let probes = query
            .inner_join(
                group_probe_permission::table.on(group_probe_permission::probe_id.eq(probe::id)),
            )
            .inner_join(
                group_user::table.on(group_user::group_id.eq(group_probe_permission::group_id)),
            )
            .filter(group_user::user_id.eq(user_id))
            .filter(
                group_probe_permission::permission
                    .eq(Permission::Read)
                    .or(group_probe_permission::permission.eq(Permission::Full)),
            )
            .distinct()
            .left_outer_join(location::table)
            .order_by(probe::ip.asc())
            .select((Option::<Location>::as_select(), Probe::as_select()))
            .load::<(Option<Location>, Probe)>(&mut conn)
            .await?;
        Ok(DbDataPerm::new(probes, (false, vec![])))
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
            .set((
                probe::mac.eq(data.mac),
                probe::ip.eq(data.ip),
                probe::last_connected_at.eq(OffsetDateTime::now_utc()),
            ))
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
    async fn create_auth(&self, data: &CreateProbe, user_id: &Id) -> DbResultSingle<Probe> {
        validate_admin(&self.pg_pool, user_id).await?;
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(probe::table)
            .values((
                probe::id.eq(data.id),
                probe::ip.eq(data.ip),
                probe::mac.eq(data.mac),
                probe::name.eq(data.name.as_ref()),
                probe::first_connected_at.eq::<Option<OffsetDateTime>>(None),
                probe::last_connected_at.eq::<Option<OffsetDateTime>>(None),
            ))
            .returning(Probe::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbDelete<Uuid, Probe> for PgProbeRepository {
    async fn delete(&self, params: &Uuid) -> DbResultMultiple<Probe> {
        let mut conn = self.pg_pool.get().await?;
        diesel::delete(probe::table.find(params))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }

    async fn delete_auth(&self, params: &Uuid, user_id: &Id) -> DbResultMultiple<Probe> {
        validate_permissions(&self.pg_pool, user_id, params, Permission::Delete).await?;
        self.delete(params).await
    }
}

impl DbUpdate<UpdateProbe, Probe> for PgProbeRepository {
    async fn update(&self, params: &UpdateProbe) -> DbResultMultiple<Probe> {
        let mut conn = self.pg_pool.get().await?;
        let probes = diesel::update(probe::table.find(&params.id))
            .set(params)
            .get_results(&mut conn)
            .await?;
        Ok(probes)
    }

    async fn update_auth(&self, params: &UpdateProbe, user_id: &Id) -> DbResultMultiple<Probe> {
        validate_permissions(&self.pg_pool, user_id, &params.id, Permission::Update).await?;
        self.update(params).await
    }
}

impl PgProbeRepository {
    pub async fn get_probe_count(&self, mut params: SelectManyProbes) -> DbResultSingle<i64> {
        let mut conn = self.pg_pool.get().await?;
        params.pagination = None;
        Self::build_select_many_query(&params)
            .count()
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }

    pub async fn forget(&self, params: &Uuid, user_id: &Id) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        validate_permissions(&self.pg_pool, user_id, params, Permission::Forget).await?;
        diesel::update(probe::table.find(params))
            .set(probe::adopted.eq(false))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn adopt(&self, params: &Uuid, user_id: &Id) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        validate_permissions(&self.pg_pool, user_id, params, Permission::Adopt).await?;
        diesel::update(probe::table.find(params))
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

    pub async fn get_probe_configs(
        &self,
        params: &Uuid,
        user_id: &Id,
    ) -> DbResultMultiple<ProbeConfig> {
        validate_permissions(&self.pg_pool, user_id, params, Permission::ModifyConfig).await?;
        self.get_probe_configs_no_auth(&params).await
    }

    pub async fn delete_probe_config(&self, params: &SelectSingleProbeConfig) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        validate_permissions(
            &self.pg_pool,
            &params.user_id,
            &params.probe_id,
            Permission::ModifyConfig,
        )
        .await?;
        diesel::delete(probe_config::table.find(params.id))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn create_probe_config(
        &self,
        params: &CreateProbeConfig,
        user_id: &Id,
    ) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        validate_permissions(
            &self.pg_pool,
            user_id,
            &params.probe_id,
            Permission::ModifyConfig,
        )
        .await?;
        diesel::insert_into(probe_config::table)
            .values(params)
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn check_permissions_for_restart(&self, params: &Uuid, user_id: &Id) -> DbResult<()> {
        validate_permissions(&self.pg_pool, user_id, params, Permission::Restart).await?;
        Ok(())
    }

    pub async fn alter_permission(&self, params: AlterProbePermission) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        validate_admin(&self.pg_pool, &params.user_id).await?;
        if params.state {
            let _ = diesel::insert_into(group_probe_permission::table)
                .values((
                    group_probe_permission::group_id.eq(params.group_id),
                    group_probe_permission::probe_id.eq(params.probe_id),
                    group_probe_permission::permission.eq(params.permission),
                ))
                .execute(&mut conn)
                .await?;
        } else {
            let _ = diesel::delete(
                group_probe_permission::table
                    .filter(group_probe_permission::probe_id.eq(params.probe_id))
                    .filter(group_probe_permission::group_id.eq(params.group_id))
                    .filter(group_probe_permission::permission.eq(params.permission)),
            )
            .execute(&mut conn)
            .await?;
        }
        Ok(())
    }

    pub async fn get_permissions(&self, params: &Uuid) -> DbResultMultiple<GroupProbePermission> {
        let mut conn = self.pg_pool.get().await?;
        let permissions = group_probe_permission::table
            .filter(group_probe_permission::probe_id.eq(params))
            .select(GroupProbePermission::as_select())
            .load::<GroupProbePermission>(&mut conn)
            .await?;
        Ok(permissions)
    }
}
