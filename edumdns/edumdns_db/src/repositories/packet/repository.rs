use crate::error::DbError;
use crate::models::{Packet, User};
use crate::repositories::common::{
    CountResult, DbCreate, DbDataPerm, DbDelete, DbReadOne, DbResultMultiple, DbResultSingle,
    DbResultSinglePerm, Permission,
};
use crate::repositories::packet::models::{CreatePacket, SelectManyPackets, SelectSinglePacket, UpdatePacket};

use crate::repositories::utilities::{validate_permissions, validate_user};
use crate::schema;
use crate::schema::packet::BoxedQuery;
use crate::schema::user;
use diesel::pg::Pg;
use diesel::sql_types::{BigInt, Cidr, Int4, Macaddr, Nullable, Text, Uuid as DieselUuid};
use diesel::{
    ExpressionMethods, PgNetExpressionMethods, PgTextExpressionMethods, QueryDsl, SelectableHelper,
    sql_query,
};
use diesel_async::AsyncPgConnection;
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use edumdns_core::app_packet::Id;
use schema::packet;

#[derive(Clone)]
pub struct PgPacketRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgPacketRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }

    pub async fn get_packet_count(
        &self,
        mut params: SelectManyPackets,
        user_id: &Id,
    ) -> DbResultSingle<i64> {
        let mut conn = self.pg_pool.get().await?;
        let user_entry = user::table
            .find(user_id)
            .select(User::as_select())
            .first(&mut conn)
            .await?;

        validate_user(&user_entry)?;
        params.pagination = None;

        if user_entry.admin {
            return build_select_many_query(&params)
                .count()
                .get_result(&mut conn)
                .await
                .map_err(DbError::from);
        }

        let query = sql_query(include_str!("queries/count.sql"))
            .bind::<BigInt, _>(user_id)
            .bind::<Nullable<BigInt>, _>(params.id)
            .bind::<Nullable<DieselUuid>, _>(params.probe_id)
            .bind::<Nullable<Macaddr>, _>(params.src_mac)
            .bind::<Nullable<Macaddr>, _>(params.dst_mac)
            .bind::<Nullable<Cidr>, _>(params.src_addr)
            .bind::<Nullable<Cidr>, _>(params.dst_addr)
            .bind::<Nullable<Int4>, _>(params.src_port)
            .bind::<Nullable<Int4>, _>(params.dst_port)
            .bind::<Nullable<Text>, _>(params.payload_string.as_ref());

        let count = query.get_result::<CountResult>(&mut conn).await?;

        Ok(count.count)
    }

    pub async fn read_many(&self, params: &SelectManyPackets) -> DbResultMultiple<Packet> {
        let mut conn = self.pg_pool.get().await?;
        PacketBackend::select_many(&mut conn, params).await
    }

    pub async fn read_many_auth(
        &self,
        params: &SelectManyPackets,
        user_id: &Id,
    ) -> DbResultMultiple<Packet> {
        let mut conn = self.pg_pool.get().await?;
        let user_entry = user::table
            .find(user_id)
            .select(User::as_select())
            .first(&mut conn)
            .await?;

        validate_user(&user_entry)?;

        if user_entry.admin {
            let packets = PacketBackend::select_many(&mut conn, params).await?;
            return Ok(packets);
        }

        let pagination = params.pagination.unwrap_or_default();

        let query = sql_query(include_str!("queries/read_many.sql"))
            .bind::<BigInt, _>(user_id)
            .bind::<Nullable<BigInt>, _>(params.id)
            .bind::<Nullable<DieselUuid>, _>(params.probe_id)
            .bind::<Nullable<Macaddr>, _>(params.src_mac)
            .bind::<Nullable<Macaddr>, _>(params.dst_mac)
            .bind::<Nullable<Cidr>, _>(params.src_addr)
            .bind::<Nullable<Cidr>, _>(params.dst_addr)
            .bind::<Nullable<Int4>, _>(params.src_port)
            .bind::<Nullable<Int4>, _>(params.dst_port)
            .bind::<Nullable<Text>, _>(params.payload_string.as_ref())
            .bind::<BigInt, _>(pagination.limit.unwrap_or(i64::MAX))
            .bind::<BigInt, _>(pagination.offset.unwrap_or(0));

        let packets = query.load::<Packet>(&mut conn).await?;
        Ok(packets)
    }

    pub async fn update_auth(&self, params: &UpdatePacket, user_id: &Id) -> DbResultMultiple<Packet> {
        let mut conn = self.pg_pool.get().await?;
        let old_probe_id = PacketBackend::select_one(&mut conn, &params.id).await?.probe_id;
        validate_permissions(&mut conn, user_id, &old_probe_id, Permission::Update).await?;
        if let Some(new_probe_id) = &params.probe_id {
            validate_permissions(&mut conn, user_id, new_probe_id, Permission::Create).await?;
        }
        PacketBackend::update(&mut conn, params).await
    }
}

impl DbReadOne<Id, Packet> for PgPacketRepository {
    async fn read_one(&self, params: &Id) -> DbResultSingle<Packet> {
        let mut conn = self.pg_pool.get().await?;
        PacketBackend::select_one(&mut conn, params).await
    }
    async fn read_one_auth(&self, params: &Id, user_id: &Id) -> DbResultSinglePerm<Packet> {
        let mut conn = self.pg_pool.get().await?;
        let p = PacketBackend::select_one(&mut conn, params).await?;
        let permissions =
            validate_permissions(&mut conn, user_id, &p.probe_id, Permission::Read).await?;
        Ok(DbDataPerm::new(p, permissions))
    }
}

impl DbReadOne<SelectSinglePacket, Packet> for PgPacketRepository {
    async fn read_one(&self, params: &SelectSinglePacket) -> DbResultSingle<Packet> {
        let mut conn = self.pg_pool.get().await?;
        PacketBackend::select_one_param(&mut conn, params).await
    }
    async fn read_one_auth(
        &self,
        params: &SelectSinglePacket,
        user_id: &Id,
    ) -> DbResultSinglePerm<Packet> {
        let mut conn = self.pg_pool.get().await?;
        let permissions =
            validate_permissions(&mut conn, user_id, &params.probe_id, Permission::Read).await?;
        let p = PacketBackend::select_one_param(&mut conn, params).await?;
        Ok(DbDataPerm::new(p, permissions))
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
                packet::payload_string.eq(data.payload_string.as_ref()),
            ))
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
    async fn create_auth(&self, data: &CreatePacket, user_id: &Id) -> DbResultSingle<Packet> {
        let mut conn = self.pg_pool.get().await?;
        validate_permissions(&mut conn, user_id, &data.probe_id, Permission::Create).await?;
        diesel::insert_into(packet::table)
            .values(data)
            .returning(Packet::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbDelete<Id, Packet> for PgPacketRepository {
    async fn delete(&self, params: &Id) -> DbResultMultiple<Packet> {
        let mut conn = self.pg_pool.get().await?;
        PacketBackend::drop(&mut conn, params).await
    }

    async fn delete_auth(&self, params: &Id, user_id: &Id) -> DbResultMultiple<Packet> {
        let mut conn = self.pg_pool.get().await?;
        let p = PacketBackend::select_one(&mut conn, params).await?;
        validate_permissions(&mut conn, user_id, &p.probe_id, Permission::Delete).await?;
        PacketBackend::drop(&mut conn, params).await
    }
}

struct PacketBackend {}

impl PacketBackend {
    async fn select_one(conn: &mut AsyncPgConnection, params: &Id) -> DbResultSingle<Packet> {
        let p = packet::table
            .find(params)
            .select(Packet::as_select())
            .first(conn)
            .await?;
        Ok(p)
    }

    async fn select_one_param(
        conn: &mut AsyncPgConnection,
        params: &SelectSinglePacket,
    ) -> DbResultSingle<Packet> {
        let p = packet::table
            .filter(packet::probe_id.eq(params.probe_id))
            .filter(packet::src_mac.eq(params.src_mac))
            .filter(packet::src_addr.eq(params.src_addr))
            .select(Packet::as_select())
            .first(conn)
            .await?;
        Ok(p)
    }

    async fn select_many(
        conn: &mut AsyncPgConnection,
        params: &SelectManyPackets,
    ) -> DbResultMultiple<Packet> {
        let query = build_select_many_query(params);
        let packets = query
            .order_by(packet::id.asc())
            .select(Packet::as_select())
            .load::<Packet>(conn)
            .await?;
        Ok(packets)
    }

    async fn drop(conn: &mut AsyncPgConnection, params: &Id) -> DbResultMultiple<Packet> {
        diesel::delete(packet::table.find(params))
            .get_results(conn)
            .await
            .map_err(DbError::from)
    }

    async fn update(conn: &mut AsyncPgConnection, params: &UpdatePacket) -> DbResultMultiple<Packet> {
        diesel::update(packet::table.find(params.id))
            .set(params)
            .get_results::<Packet>(conn)
            .await
            .map_err(DbError::from)
    }
}

fn build_select_many_query<'a>(params: &'a SelectManyPackets) -> BoxedQuery<'a, Pg> {
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

    if let Some(q) = &params.payload_string {
        query = query.filter(packet::payload_string.ilike(format!("%{q}%")))
    }

    if let Some(pagination) = params.pagination {
        query = query.limit(pagination.limit.unwrap_or(i64::MAX));
        query = query.offset(pagination.offset.unwrap_or(0));
    }
    query
}
