use crate::error::DbError;
use crate::models::{Device, PacketTransmitRequest, Probe};
use crate::repositories::common::{DbCreate, DbDelete, DbReadMany, DbReadOne, DbResultMultiple, DbResultSingle, SelectSingleById, Id, Permission};
use crate::repositories::device::models::{CreateDevice, CreatePacketTransmitRequest, SelectManyDevices, SelectSingleDevice};
use crate::schema::{device, packet_transmit_request, probe};
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use crate::repositories::probe::models::SelectSingleProbe;
use crate::repositories::utilities::validate_permissions;

#[derive(Clone)]
pub struct PgDeviceRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgDeviceRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }

    pub async fn read_packet_transmit_requests(
        &self,
        device_id: &Id,
    ) -> DbResultMultiple<PacketTransmitRequest> {
        let mut conn = self.pg_pool.get().await?;
        packet_transmit_request::table
            .filter(packet_transmit_request::device_id.eq(device_id))
            .load::<PacketTransmitRequest>(&mut conn)
            .await
            .map_err(DbError::from)
    }

    pub async fn delete_packet_transmit_request(
        &self,
        params: &Id,
    ) -> DbResultMultiple<PacketTransmitRequest> {
        let mut conn = self.pg_pool.get().await?;
        diesel::delete(packet_transmit_request::table.find(&params))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbReadOne<SelectSingleById, Device> for PgDeviceRepository {
    async fn read_one(&self, params: &SelectSingleById) -> DbResultSingle<Device> {
        let mut conn = self.pg_pool.get().await?;
        let d = device::table
            .find(params.id)
            .select(Device::as_select())
            .first(&mut conn)
            .await?;
        validate_permissions(&self.pg_pool, &SelectSingleProbe::new(params.user_id, d.probe_id), Permission::Read).await?;
        Ok(d)
    }
}



impl DbReadOne<SelectSingleDevice, Device> for PgDeviceRepository {
    async fn read_one(&self, params: &SelectSingleDevice) -> DbResultSingle<Device> {
        let mut conn = self.pg_pool.get().await?;
        if let Some(user_id) = params.user_id {
            validate_permissions(&self.pg_pool, &SelectSingleProbe::new(user_id, params.probe_id), Permission::Read).await?;
        }
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

impl DbReadMany<SelectManyDevices, (Probe, Device)> for PgDeviceRepository {
    async fn read_many(
        &self,
        params: &SelectManyDevices,
    ) -> DbResultMultiple<(Probe, Device)> {
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
            .inner_join(probe::table)
            .select((Probe::as_select(), Device::as_select()))
            .load::<(Probe, Device)>(&mut conn)
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

impl DbDelete<SelectSingleById, Device> for PgDeviceRepository {
    async fn delete(&self, params: &SelectSingleById) -> DbResultMultiple<Device> {
        let mut conn = self.pg_pool.get().await?;
        let d = self.read_one(params).await?;
        validate_permissions(&self.pg_pool, &SelectSingleProbe::new(params.user_id, d.probe_id), Permission::Delete).await?;
        diesel::delete(device::table.find(params.id))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbCreate<CreatePacketTransmitRequest, PacketTransmitRequest> for PgDeviceRepository {
    async fn create(&self, data: &CreatePacketTransmitRequest) -> DbResultSingle<PacketTransmitRequest> {
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(packet_transmit_request::table)
            .values(data)
            .returning(PacketTransmitRequest::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}
