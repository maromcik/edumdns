use crate::error::DbError;
use crate::models::{GroupProbePermission, Packet, User};
use crate::repositories::common::{
    DbCreate, DbDataPerm, DbDelete, DbReadMany, DbReadOne, DbResultMultiple, DbResultMultiplePerm,
    DbResultSingle, DbResultSinglePerm, Id, Permission,
};
use crate::repositories::packet::models::{CreatePacket, SelectManyPackets, SelectSinglePacket};

use crate::repositories::utilities::validate_permissions;
use crate::schema;
use crate::schema::packet::BoxedQuery;
use crate::schema::{group_probe_permission, group_user, probe, user};
use diesel::pg::Pg;
use diesel::{BoolExpressionMethods, ExpressionMethods, JoinOnDsl, QueryDsl, SelectableHelper};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
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
        query
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
        let query = PgPacketRepository::build_select_many_query(params);

        let user_entry = user::table
            .find(user_id)
            .select(User::as_select())
            .first(&mut conn)
            .await?;
        if user_entry.admin {
            let packets = self.read_many(params).await?;
            return Ok(DbDataPerm::new(
                packets,
                (true, vec![GroupProbePermission::full()]),
            ));
        }
        let packets = query
            .inner_join(probe::table)
            .inner_join(
                group_probe_permission::table.on(group_probe_permission::probe_id.eq(probe::id)),
            )
            .inner_join(
                group_user::table.on(group_user::group_id.eq(group_probe_permission::group_id)),
            )
            .filter(group_user::user_id.eq(user_id))
            .filter(group_probe_permission::permission.eq(Permission::Read).or(group_probe_permission::permission.eq(Permission::Full)))
            .distinct()
            .order(packet::id.asc())
            .select(Packet::as_select())
            .load::<Packet>(&mut conn)
            .await?;

        Ok(DbDataPerm::new(packets, (false, vec![])))
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
                packet::payload,
            ))
            .do_update()
            .set((
                packet::dst_mac.eq(data.dst_mac),
                packet::src_port.eq(data.src_port),
                packet::dst_port.eq(data.dst_port),
            ))
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
