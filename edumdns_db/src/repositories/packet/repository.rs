use crate::error::DbError;
use crate::models::{Packet};
use crate::repositories::common::{DbCreate, DbDelete, DbReadMany, DbReadOne, DbResultMultiple, DbResultSingle, Id};
use crate::repositories::packet::models::{CreatePacket, SelectManyPackets, SelectSingleFilter};
use crate::schema;
use diesel::{ExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use schema::packet;

#[derive(Clone)]
pub struct PgPacketRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgPacketRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }
}

impl DbReadOne<SelectSingleFilter, Packet> for PgPacketRepository {
    async fn read_one(&self, params: &SelectSingleFilter) -> DbResultSingle<Packet> {
        let mut conn = self.pg_pool.get().await?;
        packet::table
            .filter(packet::probe_id.eq(params.probe_id))
            .filter(packet::src_mac.eq(params.src_mac))
            .filter(packet::src_addr.eq(params.src_addr))
            .select(Packet::as_select())
            .first(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbReadOne<Id, Packet> for PgPacketRepository {
    async fn read_one(&self, params: &Id) -> DbResultSingle<Packet> {
        let mut conn = self.pg_pool.get().await?;
        packet::table
            .find(params)
            .select(Packet::as_select())
            .first(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbReadMany<SelectManyPackets, Packet> for PgPacketRepository {
    async fn read_many(&self, params: &SelectManyPackets) -> DbResultMultiple<Packet> {
        let mut query = packet::table.into_boxed();

        if let Some(q) = &params.probe_id {
            query = query.filter(packet::probe_id.eq(q));
        }

        if let Some(q) = &params.src_mac {
            query = query.filter(packet::src_mac.eq(q));
        }

        if let Some(q) = &params.dst_mac {
            query = query.filter(packet::dst_mac.eq(q));
        }

        if let Some(q) = &params.src_addr {
            query = query.filter(packet::src_addr.eq(q));
        }

        if let Some(q) = &params.dst_addr {
            query = query.filter(packet::dst_addr.eq(q));
        }

        if let Some(q) = &params.src_port {
            query = query.filter(packet::src_port.eq(q));
        }

        if let Some(q) = &params.dst_port {
            query = query.filter(packet::dst_port.eq(q));
        }

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        let mut conn = self.pg_pool.get().await?;
        let packets = query
            .select(Packet::as_select())
            .load::<Packet>(&mut conn)
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
            .on_conflict((packet::probe_id, packet::src_mac, packet::src_addr, packet::dst_addr, packet::payload,))
            .do_update()
            .set((packet::dst_mac.eq(data.dst_mac), packet::src_port.eq(data.src_port), packet::dst_port.eq(data.dst_port),))
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbDelete<Id, Packet> for PgPacketRepository {
    async fn delete(&self, params: &Id) -> DbResultMultiple<Packet> {
        let mut conn = self.pg_pool.get().await?;
        diesel::delete(packet::table
            .find(params))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }
}