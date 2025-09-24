use crate::error::DbError;
use crate::models::{Device, GroupProbePermission, PacketTransmitRequest, Probe, User};
use crate::repositories::common::{DbCreate, DbDataPerm, DbDelete, DbReadMany, DbReadOne, DbResult, DbResultMultiple, DbResultMultiplePerm, DbResultSingle, DbResultSinglePerm, DbUpdate, Id, Permission};
use crate::repositories::device::models::{
    CreateDevice, CreatePacketTransmitRequest, DeviceUpdatePassword, SelectManyDevices,
    SelectSingleDevice, UpdateDevice,
};
use crate::repositories::utilities::{generate_salt, hash_password, validate_permissions};
use crate::schema::device::BoxedQuery;
use crate::schema::{
    device, group_probe_permission, group_user, packet, packet_transmit_request, probe, user,
};
use diesel::pg::Pg;
use diesel::{
    ExpressionMethods, JoinOnDsl, PgNetExpressionMethods, PgTextExpressionMethods, QueryDsl,
    SelectableHelper,
};
use diesel_async::RunQueryDsl;
use diesel_async::pooled_connection::deadpool::Pool;
use diesel_async::scoped_futures::ScopedFutureExt;
use diesel_async::{AsyncConnection, AsyncPgConnection};
use std::collections::HashSet;

#[derive(Clone)]
pub struct PgDeviceRepository {
    pg_pool: Pool<AsyncPgConnection>,
}

impl PgDeviceRepository {
    pub fn new(pg_pool: Pool<AsyncPgConnection>) -> Self {
        Self { pg_pool }
    }

    pub fn build_select_many_query<'a>(params: &'a SelectManyDevices) -> BoxedQuery<'a, Pg> {
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

        if let Some(pagination) = params.pagination {
            query = query.limit(pagination.limit.unwrap_or(i64::MAX));
            query = query.offset(pagination.offset.unwrap_or(0));
        }

        query
    }

    pub async fn get_all_packet_transmit_requests(
        &self,
    ) -> DbResultMultiple<(Device, PacketTransmitRequest)> {
        let mut conn = self.pg_pool.get().await?;
        device::table
            .inner_join(packet_transmit_request::table)
            .load::<(Device, PacketTransmitRequest)>(&mut conn)
            .await
            .map_err(DbError::from)
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

    pub async fn get_device_count(&self, mut params: SelectManyDevices) -> DbResultSingle<i64> {
        let mut conn = self.pg_pool.get().await?;
        params.pagination = None;
        Self::build_select_many_query(&params)
            .count()
            .get_result(&mut conn)
            .await
            .map_err(DbError::from)
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
}

impl DbReadOne<Id, Device> for PgDeviceRepository {
    async fn read_one(&self, params: &Id) -> DbResultSingle<Device> {
        let mut conn = self.pg_pool.get().await?;
        let d = device::table
            .find(params)
            .select(Device::as_select())
            .first(&mut conn)
            .await?;
        Ok(d)
    }

    async fn read_one_auth(&self, params: &Id, user_id: &Id) -> DbResultSinglePerm<Device> {
        let d = self.read_one(params).await?;
        let permissions =
            validate_permissions(&self.pg_pool, user_id, &d.probe_id, Permission::Read).await?;
        Ok(DbDataPerm::new(d, permissions))
    }
}

impl DbReadOne<SelectSingleDevice, Device> for PgDeviceRepository {
    async fn read_one(&self, params: &SelectSingleDevice) -> DbResultSingle<Device> {
        let mut conn = self.pg_pool.get().await?;
        let d = device::table
            .filter(device::probe_id.eq(params.probe_id))
            .filter(device::mac.eq(params.mac))
            .filter(device::ip.eq(params.ip))
            .select(Device::as_select())
            .first(&mut conn)
            .await?;
        Ok(d)
    }

    async fn read_one_auth(
        &self,
        params: &SelectSingleDevice,
        user_id: &Id,
    ) -> DbResultSinglePerm<Device> {
        let permissions =
            validate_permissions(&self.pg_pool, user_id, &params.probe_id, Permission::Read)
                .await?;
        let d = self.read_one(params).await?;
        Ok(DbDataPerm::new(d, permissions))
    }
}

impl DbReadMany<SelectManyDevices, (Probe, Device)> for PgDeviceRepository {
    async fn read_many(&self, params: &SelectManyDevices) -> DbResultMultiple<(Probe, Device)> {
        let mut conn = self.pg_pool.get().await?;
        let query = PgDeviceRepository::build_select_many_query(params);
        let devices = query
            .inner_join(probe::table)
            .order_by(device::id.asc())
            .select((Probe::as_select(), Device::as_select()))
            .load::<(Probe, Device)>(&mut conn)
            .await?;

        Ok(devices)
    }

    async fn read_many_auth(
        &self,
        params: &SelectManyDevices,
        user_id: &Id,
    ) -> DbResultMultiplePerm<(Probe, Device)> {
        let mut conn = self.pg_pool.get().await?;
        let user_entry = user::table
            .find(user_id)
            .select(User::as_select())
            .first(&mut conn)
            .await?;
        if user_entry.admin {
            let devices = self.read_many(params).await?;
            return Ok(DbDataPerm::new(
                devices,
                (true, vec![GroupProbePermission::full()]),
            ));
        }
        let query = PgDeviceRepository::build_select_many_query(params);
        let ids = query
            .inner_join(probe::table)
            .select(device::id)
            .load::<Id>(&mut conn)
            .await?;

        let devices = device::table
            .filter(device::id.eq_any(&ids))
            .inner_join(probe::table)
            .inner_join(
                group_probe_permission::table.on(group_probe_permission::probe_id.eq(probe::id)),
            )
            .inner_join(
                group_user::table.on(group_user::group_id.eq(group_probe_permission::group_id)),
            )
            .filter(group_user::user_id.eq(user_id))
            .distinct()
            .order_by(device::id.asc())
            .select((
                Probe::as_select(),
                Device::as_select(),
                GroupProbePermission::as_select(),
            ))
            .load::<(Probe, Device, GroupProbePermission)>(&mut conn)
            .await?;
        let mut devices_only = Vec::default();
        let mut permissions: HashSet<GroupProbePermission> = HashSet::new();
        for device in devices {
            if device.2.permission == Permission::Full || device.2.permission == Permission::Read {
                devices_only.push((device.0, device.1));
            }

            permissions.insert(device.2);
        }
        Ok(DbDataPerm::new(
            devices_only,
            (false, Vec::from_iter(permissions)),
        ))
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

impl DbUpdate<UpdateDevice, Device> for PgDeviceRepository {
    async fn update(&self, params: &UpdateDevice) -> DbResultMultiple<Device> {
        let mut conn = self.pg_pool.get().await?;

        let devices = diesel::update(device::table.find(&params.id))
            .set(params)
            .get_results(&mut conn)
            .await?;
        Ok(devices)
    }

    async fn update_auth(&self, params: &UpdateDevice, user_id: &Id) -> DbResultMultiple<Device> {
        let mut conn = self.pg_pool.get().await?;
        let d = device::table
            .find(&params.id)
            .first::<Device>(&mut conn)
            .await?;
        validate_permissions(&self.pg_pool, user_id, &d.probe_id, Permission::Update).await?;
        let devices = self.update(params).await?;
        Ok(devices)
    }
}

impl DbDelete<Id, Device> for PgDeviceRepository {
    async fn delete(&self, params: &Id) -> DbResultMultiple<Device> {
        let mut conn = self.pg_pool.get().await?;
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

    async fn delete_auth(&self, params: &Id, user_id: &Id) -> DbResultMultiple<Device> {
        let d = self.read_one(params).await?;
        validate_permissions(&self.pg_pool, user_id, &d.probe_id, Permission::Delete).await?;
        self.delete(params).await
    }
}

impl DbCreate<CreatePacketTransmitRequest, PacketTransmitRequest> for PgDeviceRepository {
    async fn create(
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
}
