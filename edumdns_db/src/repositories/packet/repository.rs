use crate::error::DbError;
use crate::models::{GroupProbePermission, Packet, User};
use crate::repositories::common::{
    DbCreate, DbDataPerm, DbDelete, DbReadMany, DbReadOne, DbResultMultiple, DbResultMultiplePerm,
    DbResultSingle, DbResultSinglePerm, Id, Permission,
};
use crate::repositories::packet::models::{CreatePacket, SelectManyPackets, SelectSinglePacket};
use std::collections::HashSet;

use crate::repositories::utilities::{validate_permissions, validate_user};
use crate::schema;
use crate::schema::packet::BoxedQuery;
use crate::schema::{group_probe_permission, group_user, probe, user};
use diesel::pg::Pg;
use diesel::{BoolExpressionMethods, ExpressionMethods, JoinOnDsl, PgNetExpressionMethods, QueryDsl, SelectableHelper};
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use itertools::Itertools;
use schema::packet;

#[derive(Clone)]
pub struct PgPacketRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgPacketRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }

    pub fn build_select_many_query<'a>(params: &'a SelectManyPackets) -> BoxedQuery<'a, Pg> {
        let mut query = packet::table.into_boxed();

        if let Some(q) = &params.id {
            query = query.filter(packet::id.eq(q));
        }

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
            query = query.filter(packet::src_addr.is_contained_by_or_eq(q));
        }

        if let Some(q) = &params.dst_addr {
            query = query.filter(packet::dst_addr.is_contained_by_or_eq(q));
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
        query
    }

    pub async fn get_packet_count(&self, mut params: SelectManyPackets) -> DbResultSingle<i64> {
        let mut conn = self.pg_pool.get().await?;
        params.pagination = None;
        Self::build_select_many_query(&params)
            .count()
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbReadOne<SelectSinglePacket, Packet> for PgPacketRepository {
    async fn read_one(&self, params: &SelectSinglePacket) -> DbResultSingle<Packet> {
        let mut conn = self.pg_pool.get().await?;
        let p = packet::table
            .filter(packet::probe_id.eq(params.probe_id))
            .filter(packet::src_mac.eq(params.src_mac))
            .filter(packet::src_addr.eq(params.src_addr))
            .select(Packet::as_select())
            .first(&mut conn)
            .await?;
        Ok(p)
    }
    async fn read_one_auth(
        &self,
        params: &SelectSinglePacket,
        user_id: &Id,
    ) -> DbResultSinglePerm<Packet> {
        let permissions =
            validate_permissions(&self.pg_pool, user_id, &params.probe_id, Permission::Read)
                .await?;
        let p = self.read_one(params).await?;
        Ok(DbDataPerm::new(p, permissions))
    }
}

impl DbReadOne<Id, Packet> for PgPacketRepository {
    async fn read_one(&self, params: &Id) -> DbResultSingle<Packet> {
        let mut conn = self.pg_pool.get().await?;
        let p = packet::table
            .find(params)
            .select(Packet::as_select())
            .first(&mut conn)
            .await?;
        Ok(p)
    }
    async fn read_one_auth(&self, params: &Id, user_id: &Id) -> DbResultSinglePerm<Packet> {
        let p = self.read_one(params).await?;
        let permissions =
            validate_permissions(&self.pg_pool, user_id, &p.probe_id, Permission::Read).await?;
        Ok(DbDataPerm::new(p, permissions))
    }
}

impl DbReadMany<SelectManyPackets, Packet> for PgPacketRepository {
    async fn read_many(&self, params: &SelectManyPackets) -> DbResultMultiple<Packet> {
        let mut conn = self.pg_pool.get().await?;
        let query = PgPacketRepository::build_select_many_query(params);
        let packets = query
            .order_by(packet::id.asc())
            .select(Packet::as_select())
            .load::<Packet>(&mut conn)
            .await?;
        Ok(packets)
    }

    async fn read_many_auth(
        &self,
        params: &SelectManyPackets,
        user_id: &Id,
    ) -> DbResultMultiplePerm<Packet> {
        let mut conn = self.pg_pool.get().await?;
        let user_entry = user::table
            .find(user_id)
            .select(User::as_select())
            .first(&mut conn)
            .await?;

        validate_user(&user_entry)?;

        if user_entry.admin {
            let packets = self.read_many(params).await?;
            return Ok(DbDataPerm::new(
                packets,
                (true, vec![GroupProbePermission::full()]),
            ));
        }

        let query = PgPacketRepository::build_select_many_query(params);
        let packets = query
            .inner_join(probe::table)
            .inner_join(
                group_probe_permission::table.on(group_probe_permission::probe_id.eq(probe::id)),
            )
            .filter(
                group_probe_permission::permission
                    .eq(Permission::Read)
                    .or(group_probe_permission::permission.eq(Permission::Full)),
            )
            .inner_join(
                group_user::table.on(group_user::group_id.eq(group_probe_permission::group_id)),
            )
            .filter(group_user::user_id.eq(user_id))
            .order_by(packet::id.asc())
            .select(Packet::as_select())
            .load::<Packet>(&mut conn)
            .await?;

        let query = PgPacketRepository::build_select_many_query(params);
        let owned_packets = query
            .inner_join(probe::table)
            .filter(probe::owner_id.eq(user_id))
            .select(Packet::as_select())
            .load::<Packet>(&mut conn)
            .await?;

        let mut packets: HashSet<Packet> = HashSet::from_iter(packets);
        packets.extend(owned_packets);

        let packets = packets.into_iter().sorted_by_key(|p| p.id).collect::<Vec<_>>();

        Ok(DbDataPerm::new(
            packets,
            (false, vec![]),
        ))
    }
}

impl DbCreate<CreatePacket, Packet> for PgPacketRepository {
    async fn create(&self, data: &CreatePacket) -> DbResultSingle<Packet> {
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(packet::table)
            .values(data)
            .returning(Packet::as_returning())
            .on_conflict((
                packet::probe_id,
                packet::src_mac,
                packet::src_addr,
                packet::dst_addr,
                packet::dst_port,
                packet::payload_hash,
            ))
            .do_update()
            .set((
                packet::dst_mac.eq(data.dst_mac),
                packet::src_port.eq(data.src_port),
                packet::payload.eq(&data.payload),
            ))
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
    async fn create_auth(&self, data: &CreatePacket, user_id: &Id) -> DbResultSingle<Packet> {
        validate_permissions(&self.pg_pool, user_id, &data.probe_id, Permission::Create).await?;
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(packet::table)
            .values((
                packet::probe_id.eq(data.probe_id),
                packet::src_mac.eq(data.src_mac),
                packet::dst_mac.eq(data.dst_mac),
                packet::src_addr.eq(data.src_addr),
                packet::dst_addr.eq(data.dst_addr),
                packet::src_port.eq(data.src_port),
                packet::dst_port.eq(data.dst_port),
                packet::payload.eq(&data.payload),
                packet::payload_hash.eq(&data.payload_hash),
            ))
            .returning(Packet::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbDelete<Id, Packet> for PgPacketRepository {
    async fn delete(&self, params: &Id) -> DbResultMultiple<Packet> {
        let mut conn = self.pg_pool.get().await?;
        diesel::delete(packet::table.find(params))
            .get_results(&mut conn)
            .await
            .map_err(DbError::from)
    }

    async fn delete_auth(&self, params: &Id, user_id: &Id) -> DbResultMultiple<Packet> {
        let p = self.read_one(params).await?;
        validate_permissions(&self.pg_pool, user_id, &p.probe_id, Permission::Delete).await?;
        self.delete(params).await
    }
}
