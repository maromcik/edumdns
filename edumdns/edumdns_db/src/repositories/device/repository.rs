use crate::error::DbError;
use crate::models::{Device, PacketTransmitRequest, User};
use crate::repositories::common::{
    CountResult, DbCreate, DbDataPerm, DbDelete, DbReadOne, DbResult, DbResultMultiple,
    DbResultSingle, DbResultSinglePerm, DbUpdate, Permission,
};
use crate::repositories::device::models::{
    CreateDevice, CreatePacketTransmitRequest, DeviceUpdatePassword, SelectManyDevices,
    SelectSingleDevice, UpdateDevice,
};
use crate::repositories::utilities::{
    generate_salt, hash_password, validate_permissions, validate_user,
};
use crate::schema::device::BoxedQuery;
use crate::schema::{device, packet, packet_transmit_request, user};
use diesel::pg::Pg;
use diesel::sql_query;
use diesel::sql_types::{BigInt, Bool, Cidr, Int4, Macaddr, Nullable, Text, Uuid as DieselUuid};
use diesel::{
    ExpressionMethods, PgNetExpressionMethods, PgTextExpressionMethods, QueryDsl, SelectableHelper,
};
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection};
use edumdns_core::app_packet::Id;
use std::ops::DerefMut;
use time::OffsetDateTime;

#[derive(Clone)]
pub struct PgDeviceRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgDeviceRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }

    pub async fn get_all_packet_transmit_requests(
        &self,
    ) -> DbResultMultiple<(Device, PacketTransmitRequest)> {
        let mut conn = self.pg_pool.get().await?;
        let res = conn
            .deref_mut()
            .transaction::<_, DbError, _>(|c| {
                async move {
                    diesel::update(packet_transmit_request::table)
                        .set(packet_transmit_request::created_at.eq(OffsetDateTime::now_utc()))
                        .execute(c)
                        .await?;
                    let data = device::table
                        .inner_join(packet_transmit_request::table)
                        .load::<(Device, PacketTransmitRequest)>(c)
                        .await?;
                    Ok::<Vec<(Device, PacketTransmitRequest)>, DbError>(data)
                }
                .scope_boxed()
            })
            .await?;
        Ok(res)
    }

    pub async fn read_packet_transmit_request_by_user(
        &self,
        device_id: &Id,
        user_id: &Id,
    ) -> DbResultMultiple<PacketTransmitRequest> {
        let mut conn = self.pg_pool.get().await?;
        packet_transmit_request::table
            .filter(packet_transmit_request::device_id.eq(device_id))
            .filter(packet_transmit_request::user_id.eq(user_id))
            .load::<PacketTransmitRequest>(&mut conn)
            .await
            .map_err(DbError::from)
    }

    pub async fn read_packet_transmit_requests_by_device(
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

    pub async fn extend_packet_transmit_request(
        &self,
        params: &Id,
    ) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        diesel::update(packet_transmit_request::table.find(&params))
            .set(packet_transmit_request::created_at.eq(OffsetDateTime::now_utc()))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn get_device_count(
        &self,
        mut params: SelectManyDevices,
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
            .bind::<Nullable<Macaddr>, _>(params.mac)
            .bind::<Nullable<Cidr>, _>(params.ip)
            .bind::<Nullable<Int4>, _>(params.port)
            .bind::<Nullable<Text>, _>(params.name.as_ref())
            .bind::<Nullable<Bool>, _>(params.published)
            .bind::<Nullable<Bool>, _>(params.proxy);

        let result = query.get_result::<CountResult>(&mut conn).await?;
        Ok(result.count)
    }

    pub async fn update_password(&self, params: &DeviceUpdatePassword) -> DbResultSingle<Device> {
        let mut conn = self.pg_pool.get().await?;

        let device = conn
            .transaction::<_, DbError, _>(|c| {
                async move {
                    let d = device::table.find(&params.id).first::<Device>(c).await?;

                    let salt = generate_salt();
                    let password_hash = hash_password(params.new_password.clone(), &salt)?;

                    diesel::update(&d)
                        .set((
                            device::acl_pwd_hash.eq(password_hash),
                            device::acl_pwd_salt.eq(salt.to_string()),
                        ))
                        .execute(c)
                        .await?;

                    Ok::<Device, DbError>(d)
                }
                .scope_boxed()
            })
            .await?;
        Ok(device)
    }

    pub async fn toggle_publicity(
        &self,
        device_id: &Id,
        user_id: &Id,
        published: bool,
    ) -> DbResult<()> {
        let mut conn = self.pg_pool.get().await?;
        let d = device::table
            .find(&device_id)
            .first::<Device>(&mut conn)
            .await?;
        validate_permissions(&mut conn, user_id, &d.probe_id, Permission::Update).await?;
        diesel::update(device::table.find(&device_id))
            .set(device::published.eq(published))
            .execute(&mut conn)
            .await?;
        Ok(())
    }

    pub async fn create_packet_transmit_request(
        &self,
        data: &CreatePacketTransmitRequest,
    ) -> DbResultSingle<PacketTransmitRequest> {
        let mut conn = self.pg_pool.get().await?;
        diesel::insert_into(packet_transmit_request::table)
            .values(data)
            .returning(PacketTransmitRequest::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }

    pub async fn read_many(&self, params: &SelectManyDevices) -> DbResultMultiple<Device> {
        let mut conn = self.pg_pool.get().await?;
        let devices = DeviceBackend::select_many(&mut conn, params).await?;
        Ok(devices)
    }

    pub async fn read_many_auth(
        &self,
        params: &SelectManyDevices,
        user_id: &Id,
    ) -> DbResultMultiple<Device> {
        let mut conn = self.pg_pool.get().await?;
        let user_entry = user::table
            .find(user_id)
            .select(User::as_select())
            .first(&mut conn)
            .await?;

        validate_user(&user_entry)?;

        if user_entry.admin {
            let devices = DeviceBackend::select_many(&mut conn, params).await?;
            return Ok(devices);
        }

        let pagination = params.pagination.unwrap_or_default();

        let query = sql_query(include_str!("queries/read_many.sql"))
            .bind::<BigInt, _>(user_id)
            .bind::<Nullable<BigInt>, _>(params.id)
            .bind::<Nullable<DieselUuid>, _>(params.probe_id)
            .bind::<Nullable<Macaddr>, _>(params.mac)
            .bind::<Nullable<Cidr>, _>(params.ip)
            .bind::<Nullable<Int4>, _>(params.port)
            .bind::<Nullable<Text>, _>(params.name.as_ref())
            .bind::<Nullable<Bool>, _>(params.published)
            .bind::<Nullable<Bool>, _>(params.proxy)
            .bind::<BigInt, _>(pagination.limit.unwrap_or(i64::MAX))
            .bind::<BigInt, _>(pagination.offset.unwrap_or(0));

        let devices = query.load::<Device>(&mut conn).await?;
        Ok(devices)
    }
}

impl DbReadOne<Id, Device> for PgDeviceRepository {
    async fn read_one(&self, params: &Id) -> DbResultSingle<Device> {
        let mut conn = self.pg_pool.get().await?;
        let d = DeviceBackend::select_one(&mut conn, params).await?;
        Ok(d)
    }

    async fn read_one_auth(&self, params: &Id, user_id: &Id) -> DbResultSinglePerm<Device> {
        let mut conn = self.pg_pool.get().await?;
        let d = DeviceBackend::select_one(&mut conn, params).await?;
        let permissions =
            validate_permissions(&mut conn, user_id, &d.probe_id, Permission::Read).await?;
        Ok(DbDataPerm::new(d, permissions))
    }
}

impl DbReadOne<SelectSingleDevice, Device> for PgDeviceRepository {
    async fn read_one(&self, params: &SelectSingleDevice) -> DbResultSingle<Device> {
        let mut conn = self.pg_pool.get().await?;
        let d = DeviceBackend::select_one_param(&mut conn, params).await?;
        Ok(d)
    }

    async fn read_one_auth(
        &self,
        params: &SelectSingleDevice,
        user_id: &Id,
    ) -> DbResultSinglePerm<Device> {
        let mut conn = self.pg_pool.get().await?;
        let permissions =
            validate_permissions(&mut conn, user_id, &params.probe_id, Permission::Read).await?;
        let d = DeviceBackend::select_one_param(&mut conn, params).await?;
        Ok(DbDataPerm::new(d, permissions))
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
    async fn create_auth(&self, data: &CreateDevice, user_id: &Id) -> DbResultSingle<Device> {
        let mut conn = self.pg_pool.get().await?;
        validate_permissions(&mut conn, user_id, &data.probe_id, Permission::Create).await?;
        diesel::insert_into(device::table)
            .values((
                device::probe_id.eq(data.probe_id),
                device::mac.eq(data.mac),
                device::ip.eq(data.ip),
                device::port.eq(data.port),
                device::name.eq(data.name.as_ref()),
                device::discovered_at.eq::<Option<OffsetDateTime>>(None),
            ))
            .returning(Device::as_returning())
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
    }
}

impl DbUpdate<UpdateDevice, Device> for PgDeviceRepository {
    async fn update(&self, params: &UpdateDevice) -> DbResultMultiple<Device> {
        let mut conn = self.pg_pool.get().await?;
        DeviceBackend::update(&mut conn, params).await
    }

    async fn update_auth(&self, params: &UpdateDevice, user_id: &Id) -> DbResultMultiple<Device> {
        let mut conn = self.pg_pool.get().await?;
        let d = DeviceBackend::select_one(&mut conn, &params.id).await?;
        validate_permissions(&mut conn, user_id, &d.probe_id, Permission::Update).await?;
        DeviceBackend::update(&mut conn, params).await
    }
}

impl DbDelete<Id, Device> for PgDeviceRepository {
    async fn delete(&self, params: &Id) -> DbResultMultiple<Device> {
        let mut conn = self.pg_pool.get().await?;
        DeviceBackend::drop(&mut conn, params).await
    }

    async fn delete_auth(&self, params: &Id, user_id: &Id) -> DbResultMultiple<Device> {
        let mut conn = self.pg_pool.get().await?;
        let d = DeviceBackend::select_one(&mut conn, params).await?;
        validate_permissions(&mut conn, user_id, &d.probe_id, Permission::Delete).await?;
        DeviceBackend::drop(&mut conn, params).await
    }
}

struct DeviceBackend {}

impl DeviceBackend {
    async fn select_one(conn: &mut AsyncPgConnection, params: &Id) -> DbResultSingle<Device> {
        let d = device::table
            .find(params)
            .select(Device::as_select())
            .first(conn)
            .await?;
        Ok(d)
    }

    async fn select_one_param(
        conn: &mut AsyncPgConnection,
        params: &SelectSingleDevice,
    ) -> DbResultSingle<Device> {
        let d = device::table
            .filter(device::probe_id.eq(params.probe_id))
            .filter(device::mac.eq(params.mac))
            .filter(device::ip.eq(params.ip))
            .select(Device::as_select())
            .first(conn)
            .await?;
        Ok(d)
    }

    async fn select_many(
        conn: &mut AsyncPgConnection,
        params: &SelectManyDevices,
    ) -> DbResultMultiple<Device> {
        let query = build_select_many_query(params);
        let devices = query
            .order_by(device::id.asc())
            .select(Device::as_select())
            .load::<Device>(conn)
            .await?;

        Ok(devices)
    }

    async fn update(
        conn: &mut AsyncPgConnection,
        params: &UpdateDevice,
    ) -> DbResultMultiple<Device> {
        conn.transaction::<_, DbError, _>(|c| {
            async move {
                let device = DeviceBackend::select_one(c, &params.id).await?;
                let updated_devices = diesel::update(device::table.find(&params.id))
                    .set(params)
                    .get_results::<Device>(c)
                    .await?;
                if let Some(d) = updated_devices.iter().next() {
                    diesel::update(
                        packet::table
                            .filter(packet::probe_id.eq(device.probe_id))
                            .filter(packet::src_mac.eq(device.mac))
                            .filter(packet::src_addr.eq(device.ip)),
                    )
                    .set((packet::src_addr.eq(&d.ip), packet::src_mac.eq(&d.mac)))
                    .execute(c)
                    .await?;
                }
                Ok::<Vec<Device>, DbError>(updated_devices)
            }
            .scope_boxed()
        })
        .await
    }

    async fn drop(conn: &mut AsyncPgConnection, params: &Id) -> DbResultMultiple<Device> {
        conn.transaction::<_, DbError, _>(|c| {
            async move {
                let deleted_devices = diesel::delete(device::table.find(params))
                    .get_results::<Device>(c)
                    .await?;

                for d in &deleted_devices {
                    diesel::delete(
                        packet::table
                            .filter(packet::probe_id.eq(d.probe_id))
                            .filter(packet::src_mac.eq(d.mac))
                            .filter(packet::src_addr.eq(d.ip)),
                    )
                    .execute(c)
                    .await?;
                }

                Ok::<Vec<Device>, DbError>(deleted_devices)
            }
            .scope_boxed()
        })
        .await
    }
}

fn build_select_many_query<'a>(params: &'a SelectManyDevices) -> BoxedQuery<'a, Pg> {
    let mut query = device::table.into_boxed();

    if let Some(q) = &params.id {
        query = query.filter(device::id.eq(q));
    }

    if let Some(q) = &params.probe_id {
        query = query.filter(device::probe_id.eq(q));
    }

    if let Some(q) = &params.mac {
        query = query.filter(device::mac.eq(q));
    }

    if let Some(q) = &params.ip {
        query = query.filter(device::ip.is_contained_by_or_eq(q));
    }

    if let Some(q) = &params.port {
        query = query.filter(device::port.eq(q));
    }

    if let Some(q) = &params.name {
        query = query.filter(device::name.ilike(format!("%{q}%")))
    }

    if let Some(p) = &params.published {
        query = query.filter(device::published.eq(p))
    }

    if let Some(p) = &params.proxy {
        query = query.filter(device::proxy.eq(p))
    }

    if let Some(pagination) = params.pagination {
        query = query.limit(pagination.limit.unwrap_or(i64::MAX));
        query = query.offset(pagination.offset.unwrap_or(0));
    }

    query
}
