use crate::error::DbError;
use crate::models::{Device, Probe};
use crate::repositories::common::{
    DbCreate, DbReadMany, DbReadOne, DbResult, DbResultMultiple, DbResultSingle, Id,
};
use crate::repositories::device::models::{CreateDevice, SelectManyFilter};
use crate::schema;
use crate::schema::probe::dsl::probe;
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use schema::device::dsl::*;
use uuid::Uuid;

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
        device
            .find(params)
            .select(Device::as_select())
            .first(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbReadMany<SelectManyFilter, (Probe, Device)> for PgDeviceRepository {
    async fn read_many(&self, params: &SelectManyFilter) -> DbResultMultiple<(Probe, Device)> {
        let mut query = device.into_boxed();

        if let Some(q) = &params.probe_id {
            query = query.filter(probe_id.eq(q));
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

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let devices = query
            .inner_join(probe)
            .select((Probe::as_select(), Device::as_select()))
            .load::<(Probe, Device)>(&mut conn)
            .await?;

        Ok(devices)
    }
}

impl DbCreate<CreateDevice, Device> for PgDeviceRepository {
    async fn create(&self, data: &CreateDevice) -> DbResultSingle<Device> {
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(schema::device::table)
            .values(data)
            .returning(Device::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

