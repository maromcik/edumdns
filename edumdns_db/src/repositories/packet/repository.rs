use crate::error::DbError;
use crate::models::{Device, Packet, Probe};
use crate::repositories::common::{
    DbCreate, DbReadMany, DbReadOne, DbResultMultiple, DbResultSingle, Id,
};
use crate::repositories::packet::models::{CreatePacket, SelectManyFilter};
use crate::schema;
use crate::schema::probe::dsl::probe;
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use schema::packet::dsl::*;
use crate::schema::device::dsl::device;

#[derive(Clone)]
pub struct PgPacketRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgPacketRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }
}

impl DbReadOne<Id, Packet> for PgPacketRepository {
    async fn read_one(&self, params: &Id) -> DbResultSingle<Packet> {
        let mut conn = self.pg_pool.get().await?;
        packet
            .find(params)
            .select(Packet::as_select())
            .first(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbReadMany<SelectManyFilter, (Device, Packet)> for PgPacketRepository {
    async fn read_many(&self, params: &SelectManyFilter) -> DbResultMultiple<(Device, Packet)> {
        let mut query = packet.into_boxed();

        if let Some(q) = &params.device_id {
            query = query.filter(device_id.eq(q));
        }

        if let Some(q) = &params.src_mac {
            query = query.filter(src_mac.eq(q));
        }

        if let Some(q) = &params.dst_mac {
            query = query.filter(dst_mac.eq(q));
        }

        if let Some(q) = &params.src_addr {
            query = query.filter(src_addr.eq(q));
        }

        if let Some(q) = &params.dst_addr {
            query = query.filter(dst_addr.eq(q));
        }

        if let Some(q) = &params.src_port {
            query = query.filter(src_port.eq(q));
        }

        if let Some(q) = &params.dst_port {
            query = query.filter(dst_port.eq(q));
        }

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let packets = query
            .inner_join(device)
            .select((Device::as_select(), Packet::as_select()))
            .load::<(Device, Packet)>(&mut conn)
            .await?;

        Ok(packets)
    }
}

impl DbCreate<CreatePacket, Packet> for PgPacketRepository {
    async fn create(&self, data: &CreatePacket) -> DbResultSingle<Packet> {
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(schema::packet::table)
            .values(data)
            .returning(Packet::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}
