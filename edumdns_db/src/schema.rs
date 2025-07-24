// @generated automatically by Diesel CLI.

pub mod sql_types {
    #[derive(diesel::query_builder::QueryId, Clone, diesel::sql_types::SqlType)]
    #[diesel(postgres_type(name = "permission"))]
    pub struct Permission;
}

diesel::table! {
    device (id) {
        id -> Int8,
        probe_id -> Uuid,
        mac -> Macaddr,
        ip -> Cidr,
        port -> Int4,
        duration -> Nullable<Float8>,
        interval -> Nullable<Float8>,
    }
}

diesel::table! {
    group (id) {
        id -> Int8,
        name -> Text,
    }
}

diesel::table! {
    use diesel::sql_types::*;
    use super::sql_types::Permission;

    group_probe_permission (group_id, probe_id) {
        group_id -> Int8,
        probe_id -> Uuid,
        permission -> Permission,
    }
}

diesel::table! {
    group_user (user_id, group_id) {
        group_id -> Int8,
        user_id -> Int8,
    }
}

diesel::table! {
    location (id) {
        id -> Int8,
        name -> Text,
    }
}

diesel::table! {
    packet (id) {
        id -> Int8,
        device_id -> Int8,
        src_mac -> Macaddr,
        dst_mac -> Macaddr,
        src_addr -> Cidr,
        dst_addr -> Cidr,
        src_port -> Int4,
        dst_port -> Int4,
        payload -> Bytea,
    }
}

diesel::table! {
    probe (id) {
        id -> Uuid,
        owner_id -> Nullable<Int8>,
        location_id -> Nullable<Int8>,
        adopted -> Bool,
        mac -> Macaddr,
        ip -> Cidr,
        port -> Int4,
        vlan -> Nullable<Int4>,
    }
}

diesel::table! {
    probe_config (probe_id) {
        probe_id -> Uuid,
        interface -> Text,
        filter -> Text,
    }
}

diesel::table! {
    user (id) {
        id -> Int8,
        email -> Text,
        name -> Text,
        surname -> Text,
        password_hash -> Text,
        password_salt -> Text,
        admin -> Bool,
        created_at -> Timestamptz,
        edited_at -> Timestamptz,
        deleted_at -> Nullable<Timestamptz>,
    }
}

diesel::joinable!(device -> probe (probe_id));
diesel::joinable!(group_probe_permission -> group (group_id));
diesel::joinable!(group_probe_permission -> probe (probe_id));
diesel::joinable!(group_user -> group (group_id));
diesel::joinable!(group_user -> user (user_id));
diesel::joinable!(packet -> device (device_id));
diesel::joinable!(probe -> location (location_id));
diesel::joinable!(probe -> user (owner_id));
diesel::joinable!(probe_config -> probe (probe_id));

diesel::allow_tables_to_appear_in_same_query!(
    device,
    group,
    group_probe_permission,
    group_user,
    location,
    packet,
    probe,
    probe_config,
    user,
);
