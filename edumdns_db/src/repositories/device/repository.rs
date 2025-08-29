use crate::error::DbError;
use crate::models::{Device,  Probe};
use crate::repositories::common::{DbCreate, DbDelete, DbReadMany, DbReadOne, DbResultMultiple, DbResultSingle, Id};
use crate::repositories::device::models::{CreateDevice, SelectManyDevices, SelectSingleFilter};
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use crate::schema::device;
use crate::schema::probe::dsl::probe;

#[derive(Clone)]
pub struct PgDeviceRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgDeviceRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }
}

impl DbReadOne<Id, Device> for PgDeviceRepository {
    async fn read_one(&self, params: &Id) -> DbResultSingle<Device> {
        let mut conn = self.pg_pool.get().await?;
        device::table
            .find(params)
            .select(Device::as_select())
            .first(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbReadOne<SelectSingleFilter, Device> for PgDeviceRepository {
    async fn read_one(&self, params: &SelectSingleFilter) -> DbResultSingle<Device> {
        let mut conn = self.pg_pool.get().await?;
        device::table
            .filter(device::probe_id.eq(params.probe_id))
            .filter(device::mac.eq(params.mac))
            .filter(device::ip.eq(params.ip))
            .select(Device::as_select())
            .first(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbReadMany<SelectManyDevices, (Option<Probe>, Device)> for PgDeviceRepository {
    async fn read_many(&self, params: &SelectManyDevices) -> DbResultMultiple<(Option<Probe>, Device)> {
        let mut query = device::table.into_boxed();

        if let Some(q) = &params.probe_id {
            query = query.filter(device::probe_id.eq(q));
        }

        if let Some(q) = &params.mac {
            query = query.filter(device::mac.eq(q));
        }

        if let Some(q) = &params.ip {
            query = query.filter(device::ip.eq(q));
        }

        if let Some(q) = &params.port {
            query = query.filter(device::port.eq(q));
        }

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let devices = query
            .left_outer_join(probe)
            .select((Option::<Probe>::as_select(), Device::as_select()))
            .load::<(Option<Probe>, Device)>(&mut conn)
            .await?;

        Ok(devices)
    }
}

impl DbCreate<CreateDevice, Device> for PgDeviceRepository {
    async fn create(&self, data: &CreateDevice) -> DbResultSingle<Device> {
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(device::table)
            .values(data)
            .returning(Device::as_returning())
            .on_conflict((device::probe_id, device::mac, device::ip))
            .do_update()
            .set((device::port.eq(data.port),))
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbDelete<Id, Device> for PgDeviceRepository {
    async fn delete(&self, params: &Id) -> DbResultMultiple<Device> {
        let mut conn = self.pg_pool.get().await?;
        diesel::delete(device::table
            .find(params))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }
}